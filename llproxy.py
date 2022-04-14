import os
import _winapi
import ctypes
import asyncio
import subprocess
from argparse import ArgumentParser
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum, Enum
from typing import Callable, List, Any


"""
EXAMPLE PACKET

# packet type
\x00\x06
# object name
\x00\x00\x00\x16
\x00L\x00L\x00A\x00c\x00c\x00e\x00s\x00s\x00I\x00p\x00c
# call type
\x00\x00\x00\x00
# method index
\x00\x00\x00\x0c
# arg list size
\x00\x00\x00\x03
# first arg
\x00\x00\x04\x00 # type id (user)
\x00 # is_null
\x00\x00\x00\x1a # custom type name len
ll_access::DramIdentifier\x00 # custom type name
\x00\x00\x00\x00\x00\x00\x00\x00Z

# second arg
\x00\x00\x00$ # ushort
\x00 # is null
\x00E # short int value

# third arg
\x00\x00\x00\x02 # type int
\x00 # is null
\xff\xff\xff\xfe # int value

\x00\x00\x00\x0b # packet serial id
\xff\xff\xff\xff # packet property index
"""


URI_MAPPING_SIZE = 64
URI_MAPPING_NAME = "Global\\CorsairLLAccessServiceAddress"


class PacketType(IntEnum):
    Invalid = 0
    Handshake = 1
    InitPacket = 2
    InitDynamicPacket = 3
    AddObject = 4
    RemoveObject = 5
    InvokePacket = 6
    InvokeReplyPacket = 7
    PropertyChangePacket = 8
    ObjectList = 9
    Ping = 10
    Pong = 11


class PacketParser:
    __slots__ = ("data", "default_byteorder")

    def __init__(self, data, default_byteorder="big"):
        self.data = memoryview(data)
        self.default_byteorder = default_byteorder

    def skip(self, size):
        self.data = self.data[size:]

    def read_bytes(self, size):
        assert len(self.data) >= size
        res = self.data[:size]
        self.skip(size)
        return res

    def get_byteorder(self, byteorder=None):
        if byteorder is None:
            return self.default_byteorder
        return byteorder

    def read_int(self, size, signed=True, byteorder=None):
        byteorder = self.get_byteorder(byteorder)
        data = self.read_bytes(size)
        return int.from_bytes(data, byteorder=byteorder, signed=signed)

    def read_bool(self):
        return self.read_bytes(1) != b"\0"

    def read_uint(self, size, byteorder=None):
        return self.read_int(size, signed=False, byteorder=byteorder)

    def read_utf16(self, header_size=4, byteorder=None):
        byteorder = self.get_byteorder(byteorder)
        size = self.read_uint(header_size, byteorder=byteorder)
        data = self.read_bytes(size)

        if byteorder == "big":
            res = bytearray()
            assert size % 2 == 0
            for i in range(size // 2):
                res.append(data[i * 2 + 1])
                res.append(data[i * 2])
            data = res
        return bytes(data).decode("utf-16")

    def read_utf8(self, header_size=4, byteorder=None):
        byteorder = self.get_byteorder(byteorder)
        size = self.read_uint(header_size, byteorder=byteorder)
        data = self.read_bytes(size)
        return bytes(data).decode("utf-8")


def open_shmem(name, size, writable=False, create=False):
    mode = _winapi.FILE_MAP_READ
    if writable:
        mode |= _winapi.FILE_MAP_WRITE

    # create the mapping
    if create:
        create_mode = _winapi.PAGE_READONLY
        if writable:
            create_mode = _winapi.PAGE_READWRITE
        handle = _winapi.CreateFileMapping(
             _winapi.INVALID_HANDLE_VALUE,
             _winapi.NULL,
             create_mode,
             (size >> 32) & 0xFFFFFFFF,
             size & 0xFFFFFFFF,
             name
        )
    else:
        handle = _winapi.OpenFileMapping(mode, False, name)

    # map it into the address space
    try:
        ptr = ctypes.c_void_p(_winapi.MapViewOfFile(handle, mode, 0, 0, size))
        return ctypes.cast(ptr, ctypes.POINTER(ctypes.c_byte * size))[0]
    finally:
        _winapi.CloseHandle(handle)


@contextmanager
def patch_shmem(mem, new_value):
    backup = bytes(mem)
    try:
        mem[:] = new_value
        yield
    finally:
        mem[:] = backup


def encode_shmem_port(port: int) -> bytes:
    res = bytearray(b"tcp://127.0.0.1:")
    res += str(port).encode()
    res += b"\0" * (URI_MAPPING_SIZE - len(res))
    return bytes(res)


def decode_shmem_port(shmem: bytes) -> int:
    clean_shmem = bytes(shmem).rstrip(b"\0")
    proto, host, port = clean_shmem.split(b":")
    assert proto == b"tcp"
    assert host == b"//127.0.0.1"
    return int(port)


class PacketDirection(Enum):
    INBOUND = 0
    OUTBOUND = 1


@dataclass
class LLProxy:
    server: asyncio.Server
    target_host: str
    target_port: int
    packet_callback: Callable[[PacketDirection, bytes], None]


    @staticmethod
    async def create(target_host: str, target_port: int, packet_callback) -> "LLProxy":
        proxy = LLProxy(None, target_host, target_port, packet_callback)
        server = await asyncio.start_server(proxy.handle_client, '127.0.0.1', 0)
        proxy.server = server
        return proxy

    @property
    def proxy_port(self):
        return self.server.sockets[0].getsockname()[1]

    async def packet_pipe(self, direction, reader, writer):
        try:
            while True:
                packet_size_data = await reader.readexactly(4)
                packet_size = int.from_bytes(packet_size_data, byteorder="big", signed=False)
                packet_data = await reader.readexactly(packet_size)
                self.packet_callback(direction, packet_data)
                writer.write(packet_size_data + packet_data)
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()

    async def handle_client(self, local_reader, local_writer):
        try:
            print("got a connection")
            remote_reader, remote_writer = await asyncio.open_connection(self.target_host, self.target_port)
            pipe1 = self.packet_pipe(PacketDirection.INBOUND, local_reader, remote_writer)
            pipe2 = self.packet_pipe(PacketDirection.OUTBOUND, remote_reader, local_writer)
            await asyncio.gather(pipe1, pipe2)
        finally:
            local_writer.close()
            remote_writer.close()

async def service(*args):
    proc = await asyncio.create_subprocess_exec("C:\\Windows\\System32\\net.exe", *args)
    await proc.wait()


# https://github.com/qt/qtbase/blob/dev/src/corelib/kernel/qmetatype.h
class VariantType(IntEnum):
    Invalid = 0
    Bool = 1
    Int = 2
    UInt = 3
    LongLong = 4
    ULongLong = 5
    Double = 6
    Char = 7
    Map = 8
    List = 9
    String = 10
    StringList = 11
    ByteArray = 12
    UShort = 36
    UChar = 37
    UserType = 1024

def deserialize_usertype(parser: PacketParser):
    typename = parser.read_utf8().rstrip("\0")
    if typename == "ll_access::DramIdentifier":
        unknown_flag = parser.read_bool()
        ram_id = parser.read_uint(8)
        return (unknown_flag, ram_id)
    if typename == "QVector<QPair<ushort,uchar> >":
        vector_size = parser.read_uint(4)
        vector = []
        for _ in range(vector_size):
            addr = parser.read_uint(2)
            value = parser.read_uint(1)
            vector.append((addr, value))
        return vector
    return f"missing handler for {typename}"



VARIANT_CONVERTERS: Callable[[PacketParser], Any] = {
    VariantType.Invalid: None,
    VariantType.Bool: lambda parser: parser.read_bool(),
    VariantType.Int: lambda parser: parser.read_int(4),
    VariantType.UInt: lambda parser: parser.read_uint(4),
    VariantType.LongLong: lambda parser: parser.read_int(8),
    VariantType.ULongLong: lambda parser: parser.read_uint(8),
    VariantType.Double: None,
    VariantType.Char: lambda parser: parser.read_bytes(1),
    VariantType.Map: None,
    VariantType.List: None,
    VariantType.String: lambda parser: parser.read_utf8(),
    VariantType.StringList: None,
    VariantType.ByteArray: lambda parser: parser.read_bytes(),
    VariantType.UShort: lambda parser: parser.read_uint(2),
    VariantType.UChar: lambda parser: parser.read_uint(1),
    VariantType.UserType: deserialize_usertype,
}


# https://github.com/qt/qtbase/blob/dev/src/corelib/kernel/qvariant.cpp
def read_variant(parser: PacketParser):
    type_id = parser.read_uint(4)
    is_null = parser.read_bool()

    try:
        type = VariantType(type_id)
    except ValueError:
        return f"invalid type id {type_id}: {bytes(parser.data)}"

    converter = VARIANT_CONVERTERS[type]
    if converter is None:
        return f"missing type handler for {type.name}: {bytes(parser.data)}"
    value = converter(parser)
    if is_null:
        return None
    return value


def read_variant_list(parser: PacketParser):
    list_size = parser.read_uint(4)
    return [read_variant(parser) for _ in range(list_size)]


class CallKind(IntEnum):
    InvokeMetaMethod = 0
    ReadProperty = 1
    WriteProperty = 2
    ResetProperty = 3
    CreateInstance = 4
    IndexOfMethod = 5
    RegisterPropertyMetaType = 6
    RegisterMethodArgumentMetaType = 7
    BindableProperty = 8
    CustomCall = 9


METHOD_METADATA = {
    ("LLAccessIpc", 0): ("InitiateConnection", []),

    ("LLAccessIpc", 2): ("NotifyConnectionActive", ["qulonglong"]),
    ("LLAccessIpc", 3): ("GetSystemInfo", []),
    ("LLAccessIpc", 4): ("GetChipsetInfo", []),
    ("LLAccessIpc", 5): ("SMBusGetControllerCount", []),
    ("LLAccessIpc", 6): ("SMBusGetCaps", ["uint64_t"]),
    ("LLAccessIpc", 7): ("SMBusGetBlockMaxSize", ["uint64_t"]),
    ("LLAccessIpc", 8): ("SMBusSetDefaultLockTimeout", ["int"]),
    ("LLAccessIpc", 9): ("SMBusSetDefaultOperationTimeout", ["int"]),
    ("LLAccessIpc", 10): ("SMBusSetCPUOffloadMask", ["uint32_t"]),
    ("LLAccessIpc", 11): ("EnumMemoryModules", []),
    ("LLAccessIpc", 12): ("SMBusReadByte", ["DramIdentifier", "uint16_t", "int"]),

    ("LLAccessIpc", 14): ("SMBusWriteByte", ["DramIdentifier", "uint16_t", "uint8_t", "int"]),

    ("LLAccessIpc", 18): ("SMBusWriteByteCmdList", ["DramIdentifier", "CommandList", "int"]),

    ("LLAccessIpc", 22): ("SetPropertyIfRequired", ["DramIdentifier", "uint16_t", "uint8_t", "int"]),
    ("LLAccessIpc", 23): ("SMBusLock", ["uint64_t", "int"]),
    ("LLAccessIpc", 24): ("SMBusUnlock", ["uint64_t"]),
}


def get_method_name(object_name, index):
    meta = METHOD_METADATA.get((object_name, index))
    if meta is not None:
        return meta[0]
    return None


def method_call_repr(object_name, index, arg_values):
    meta = METHOD_METADATA.get((object_name, index))
    if meta is not None:
        method_name, arg_types = meta
        assert len(arg_types) == len(arg_values), f"metadata mismatch for {method_name}"
        args_repr = ", ".join(
            f"/* {arg_type} */ {arg_value}"
            for arg_value, arg_type
            in zip(arg_values, arg_types)
        )
        return f"{method_name}({args_repr})"
    args_repr = ", ".join(map(str, arg_values))
    return f"{index}({args_repr})"


def process_invoke_packet(options, direction, parser: PacketParser):
    object_name = parser.read_utf16()
    call_kind_id = parser.read_uint(4)
    index = parser.read_uint(4)
    args = read_variant_list(parser)
    parser.skip(-8)
    serial_id = parser.read_uint(4)
    property_index = parser.read_int(4)
    call_kind = CallKind(call_kind_id)

    method_name = get_method_name(object_name, index)
    if not options.filter or method_name in options.filter:
        call_repr = method_call_repr(object_name, index, args)
        print(f"[{direction.name.lower()}] >>> {call_kind.name} {object_name}::{call_repr} -> #{serial_id} prop {property_index}")


def process_invoke_reply_packet(options, direction, parser: PacketParser):
    object_name = parser.read_utf16()
    serial_id = parser.read_uint(4)
    value = read_variant(parser)
    print(f"[{direction.name.lower()}] <<< reply {object_name}#{serial_id} = {value}")


PACKET_TYPE_HANDLERS = {
    PacketType.InvokePacket: process_invoke_packet,
    PacketType.InvokeReplyPacket: process_invoke_reply_packet,
}


async def main(args: List[str] = None):
    arg_parser = ArgumentParser(description="Run the CueLLAccess proxy")
    arg_parser.add_argument("--service-logs", action='store_true', help="Show the logs of the official service")
    arg_parser.add_argument("--log-packets", action='store_true', help="Show the raw packets")
    arg_parser.add_argument("-f", "--filter", action='append', help="Filter by method name")
  
    options = arg_parser.parse_args(args=None)

    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        print("please run this script as administrator")
        exit(1)

    print("stopping the managed service")
    await service("stop", "CorsairLLAService")

    print("running the service manually")
    service_env = {**os.environ, "QT_LOGGING_RULES": "*=true"}
    service_io = (None if options.service_logs else subprocess.DEVNULL)
    service_proc = await asyncio.create_subprocess_exec(
        "C:\\Program Files\\Corsair\\CORSAIR iCUE 4 Software\\CueLLAccessService.exe", "-e",
        env=service_env,
        stdout=service_io,
        stderr=service_io,
    )

    def process_packet(direction, packet):
        if options.log_packets:
            print(f"[{direction.name.lower()}] packet {packet}")
        parser = PacketParser(packet)
        packet_type = PacketType(parser.read_uint(2))
        handler = PACKET_TYPE_HANDLERS.get(packet_type)
        if handler is None:
            print(f"[{direction.name.lower()}] {packet_type.name}")
        else:
            handler(options, direction, parser)

    try:
        print("waiting a bit for the service to create the memory mapping")
        await asyncio.sleep(3)

        try:
            shmem = open_shmem(URI_MAPPING_NAME, URI_MAPPING_SIZE, writable=True)
        except FileNotFoundError:
            print("could not create the shared memory mapping")
            print("please start CueLLAccessService")
            exit(1)

        original_port = decode_shmem_port(shmem)
        proxy = await LLProxy.create("127.0.0.1", original_port, process_packet)

        print(f"original port: {original_port}")
        print(f"proxy port: {proxy.proxy_port}")

        with patch_shmem(shmem, encode_shmem_port(proxy.proxy_port)):
            try:
                while True:
                    await asyncio.sleep(42)
            finally:
                proxy.server.close()
                await proxy.server.wait_closed()
    finally:
        print("stopping the manually started service")
        service_proc.terminate()
        await service_proc.wait()
        print("restarting the managed service")
        await service("start", "CorsairLLAService")



if __name__ == "__main__":
    asyncio.run(main())
