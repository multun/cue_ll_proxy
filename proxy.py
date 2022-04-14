import os
import _winapi
import ctypes
import asyncio
import subprocess
from argparse import ArgumentParser
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum, Enum
from typing import Callable, List


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

    def read_uint(self, size, byteorder=None):
        return self.read_int(size, signed=False, byteorder=byteorder)

    def read_utf16(self, header_size=4, byteorder=None):
        byteorder = self.get_byteorder(byteorder)
        size = self.read_uint(header_size, byteorder=byteorder)
        data = self.read_bytes(size)
        print("read string data", bytes(data))

        if byteorder == "big":
            res = bytearray()
            assert size % 2 == 0
            for i in range(size // 2):
                res.append(data[i * 2 + 1])
                res.append(data[i * 2])
            data = res
        return data.decode("utf-16")


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


def process_invoke_packet(direction, packet_type, parser):
    realm = parser.read_utf16()
    print(f"[{direction.name.lower()}] invoke @{realm}")


PACKET_TYPE_HANDLERS = {
    PacketType.InvokePacket: process_invoke_packet,
}


def process_packet(direction, packet):
    print(f"[{direction.name.lower()}] packet {packet}")
    parser = PacketParser(packet)
    packet_type = PacketType(parser.read_uint(2))
    handler = PACKET_TYPE_HANDLERS.get(packet_type)
    if handler is None:
        print(f"[{direction.name.lower()}] {packet_type.name}")
    else:
        handler(direction, packet_type, parser)


async def main(args: List[str] = None):
    arg_parser = ArgumentParser(description="Run the CueLLAccess proxy")
    arg_parser.add_argument('--service-logs', action='store_true', help="Show the logs of the official service")
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