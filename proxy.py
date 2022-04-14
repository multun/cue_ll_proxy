import os
import _winapi
import ctypes
import asyncio
import subprocess
from argparse import ArgumentParser
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum, Enum
from tkinter import Pack
from typing import Callable, List, Any


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
        return data.decode("utf-16")

    def read_utf8(self, header_size=4, byteorder=None):
        byteorder = self.get_byteorder(byteorder)
        size = self.read_uint(header_size, byteorder=byteorder)
        data = self.read_bytes(size)
        return data.decode("utf-8")


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


# https://github.com/qt/qtbase/blob/dev/src/corelib/kernel/qvariant.h
class VariantType(IntEnum):
    Invalid = 0,
    Bool = 1,
    Int = 2,
    UInt = 3,
    LongLong = 4,
    ULongLong = 5,
    Double = 6,
    Char = 7,
    Map = 8,
    List = 9,
    String = 10,
    StringList = 11,
    ByteArray = 12,
    UserType = 1024,


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
    VariantType.UserType: None,
}


# https://github.com/qt/qtbase/blob/dev/src/corelib/kernel/qvariant.cpp
def read_variant(parser: PacketParser):
    type_id = parser.read_uint(4)
    is_null = parser.read_bool()

    type = VariantType(type_id)
    converter = VARIANT_CONVERTERS[type]
    if converter is None:
        return f"missing type handler for {type.name}"
    value = converter(parser)
    if is_null:
        return None
    return value


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


METHOD_NAMES = {
    ("LLAccessIpc", 0): "InitiateConnection()",

    ("LLAccessIpc", 2): "NotifyConnectionActive(qulonglong)",    
    ("LLAccessIpc", 3): "GetSystemInfo()",
    ("LLAccessIpc", 4): "GetChipsetInfo()",    
    ("LLAccessIpc", 5): "SMBusGetControllerCount()",
    ("LLAccessIpc", 6): "SMBusGetCaps(uint64_t)",
    ("LLAccessIpc", 7): "SMBusGetBlockMaxSize(uint64_t)",
    ("LLAccessIpc", 8): "SMBusSetDefaultLockTimeout(int)",
    ("LLAccessIpc", 9): "SMBusSetDefaultOperationTimeout(int)",
    ("LLAccessIpc", 10): "SMBusSetCPUOffloadMask(uint32_t)",
    ("LLAccessIpc", 11): "EnumMemoryModules()",
    ("LLAccessIpc", 12): "SMBusReadByte(ll_access::DramIdentifier,uint16_t,int)",

    ("LLAccessIpc", 14): "SMBusWriteByte(ll_access::DramIdentifier,uint16_t,uint8_t,int)",

    ("LLAccessIpc", 18): "SMBusWriteByteCmdList(ll_access::DramIdentifier,ll_access::CommandList,int)",

    ("LLAccessIpc", 22): "SetPropertyIfRequired(ll_access::DramIdentifier,uint16_t,uint8_t,int)",
    ("LLAccessIpc", 23): "SMBusLock(uint64_t,int)",
    ("LLAccessIpc", 24): "SMBusUnlock(uint64_t)",
}


"""
    in >> call;
    in >> index;
    const bool success = deserializeQVariantList(in, args);
    Q_ASSERT(success);
    Q_UNUSED(success)
    in >> serialId;
    in >> propertyIndex;
"""
def process_invoke_packet(direction, packet_type, parser: PacketParser):
    name = parser.read_utf16()
    call_kind_id = parser.read_uint(4)
    index = parser.read_uint(4)
    # TODO: read variant list
    # TODO: read serial ID
    # TODO: read property index
    call_kind = CallKind(call_kind_id)
    call_name = METHOD_NAMES.get((name, index), index)
    print(f"[{direction.name.lower()}] >>> {call_kind.name} {name}::{call_name}")


def process_invoke_reply_packet(direction, packet_type, parser: PacketParser):
    name = parser.read_utf16()
    serial_id = parser.read_uint(4)
    value = read_variant(parser)
    print(f"[{direction.name.lower()}] <<< reply {name}#{serial_id} = {value}")

PACKET_TYPE_HANDLERS = {
    PacketType.InvokePacket: process_invoke_packet,
    PacketType.InvokeReplyPacket: process_invoke_reply_packet,
}


async def main(args: List[str] = None):
    arg_parser = ArgumentParser(description="Run the CueLLAccess proxy")
    arg_parser.add_argument('--service-logs', action='store_true', help="Show the logs of the official service")
    arg_parser.add_argument('--log-packets', action='store_true', help="Show the raw packets")
    
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
            handler(direction, packet_type, parser)

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