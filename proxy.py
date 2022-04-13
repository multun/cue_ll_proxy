import _winapi
import ctypes

def open_shmem(name, size, writable=False, create=False):
    mode = _winapi.FILE_MAP_READ
    if writable:
        mode |= _winapi.FILE_MAP_READ

    # create the mapping
    if create:
        handle = _winapi.CreateFileMapping(
             _winapi.INVALID_HANDLE_VALUE,
             _winapi.NULL,
             _winapi.PAGE_READWRITE,
             (size >> 32) & 0xFFFFFFFF,
             size & 0xFFFFFFFF,
             name
        )
    else:
        handle = _winapi.OpenFileMapping(
            _winapi.FILE_MAP_READ,
            False,
            name
        )

    # map it into the address space
    try:
        ptr = ctypes.c_void_p(_winapi.MapViewOfFile(handle, mode, 0, 0, size))
        return ctypes.cast(ptr, ctypes.POINTER(ctypes.c_byte * size))[0]
    finally:
        _winapi.CloseHandle(h_map)


mem = open_shmem("Global\\CorsairLLAccessServiceAddress", 64, writable=True)
print(bytes(mem))
