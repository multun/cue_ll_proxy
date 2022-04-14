import _winapi
import ctypes
import asyncio
from json import encoder
import time
from contextlib import contextmanager


URI_MAPPING_SIZE = 64
URI_MAPPING_NAME = "Global\\CorsairLLAccessServiceAddress"


def open_shmem(name, size, writable=False, create=False):
    # create the mapping
    if create:
        mode = _winapi.PAGE_READONLY
        if writable:
            mode = _winapi.PAGE_READWRITE
        handle = _winapi.CreateFileMapping(
             _winapi.INVALID_HANDLE_VALUE,
             _winapi.NULL,
             mode,
             (size >> 32) & 0xFFFFFFFF,
             size & 0xFFFFFFFF,
             name
        )
    else:
        mode = _winapi.FILE_MAP_READ
        if writable:
            mode = _winapi.FILE_MAP_WRITE
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


try:
    shmem = open_shmem(URI_MAPPING_NAME, URI_MAPPING_SIZE, writable=True)
except FileNotFoundError:
    print("please start CueLLAccessService")
    exit(1)

original_port = decode_shmem_port(shmem)
hook_port = 4242  # TODO: make a TCP server listen

print(f"original port: {original_port}")
print(f"hook port: {hook_port}")

with patch_shmem(shmem, encode_shmem_port(hook_port)):
    # TODO: actually redirect stuff
    time.sleep(60)
