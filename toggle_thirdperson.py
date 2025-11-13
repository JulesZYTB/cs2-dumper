# Converted from toggle_thirdperson.cpp to Python
# Uses pyMeaw if available; falls back to ctypes WinAPI when not installed.
# Note: Running this script requires admin privileges and is potentially unsafe.

import struct
import sys
import ctypes
from ctypes import wintypes

# offsets (same as in the provided C++ file)
CInput_OffsetFromModule = 0x1E28800  # dwCSGOInput
ThirdPerson_Offset = 0x24F0          # m_thirdPersonHeading (QAngle)

# Helper: try to import pyMeow (pyMeow) and provide wrappers
USE_PYMEOW = False
pm = None
try:
    import pyMeow as pm
    USE_PYMEOW = True
except Exception:
    USE_PYMEOW = False


# Fallback WinAPI wrappers (ctypes)
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_ALL_ACCESS = 0x1F0FFF

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]

Kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

CreateToolhelp32Snapshot = Kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32First = Kernel32.Process32FirstW
Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32First.restype = wintypes.BOOL

Process32Next = Kernel32.Process32NextW
Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32Next.restype = wintypes.BOOL

Module32FirstW = Kernel32.Module32FirstW
Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
Module32FirstW.restype = wintypes.BOOL

Module32NextW = Kernel32.Module32NextW
Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
Module32NextW.restype = wintypes.BOOL

OpenProcess = Kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = Kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = Kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

CloseHandle = Kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


def get_process_id(process_name: str) -> int:
    if USE_PYMEOW:
        try:
            for p in pm.processes():
                if p.name.lower() == process_name.lower():
                    return p.pid
        except Exception:
            pass

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value:
        return 0

    if not Process32First(snap, ctypes.byref(pe32)):
        CloseHandle(snap)
        return 0

    while True:
        if pe32.szExeFile.lower() == process_name.lower():
            pid = pe32.th32ProcessID
            CloseHandle(snap)
            return pid
        if not Process32Next(snap, ctypes.byref(pe32)):
            break

    CloseHandle(snap)
    return 0


def get_module_base(pid: int, module_name: str) -> int:
    if USE_PYMEOW:
        try:
            for m in pm.modules(pid):
                if m.name.lower() == module_name.lower():
                    return m.base
        except Exception:
            pass

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == wintypes.HANDLE(-1).value:
        return 0

    me32 = MODULEENTRY32W()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32W)
    if not Module32FirstW(snap, ctypes.byref(me32)):
        CloseHandle(snap)
        return 0

    while True:
        if me32.szModule.lower() == module_name.lower():
            base = me32.modBaseAddr
            CloseHandle(snap)
            return base
        if not Module32NextW(snap, ctypes.byref(me32)):
            break

    CloseHandle(snap)
    return 0


def read_qangle(h_process, address: int):
    # read 3 floats
    buf = (ctypes.c_char * 12)()
    bytes_read = ctypes.c_size_t(0)
    ok = ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, 12, ctypes.byref(bytes_read))
    if not ok or bytes_read.value != 12:
        return None
    data = bytes(buf[:12])
    return struct.unpack('fff', data)


def write_qangle(h_process, address: int, q):
    data = struct.pack('fff', *q)
    bytes_written = ctypes.c_size_t(0)
    ok = WriteProcessMemory(h_process, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written))
    return ok and bytes_written.value == len(data)


def toggle_third_person_python():
    pid = get_process_id('cs2.exe')
    if pid == 0:
        print('CS2 process not found.')
        return 1

    h_proc = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        print('Failed to open process.')
        return 1

    base = get_module_base(pid, 'client.dll')
    if base == 0:
        print('Failed to get module base address.')
        CloseHandle(h_proc)
        return 1

    # dwCSGOInput is a pointer stored at (client.dll base + CInput_OffsetFromModule).
    # We must read that pointer and then add the member offset to it.
    ptr_buf = (ctypes.c_ubyte * ctypes.sizeof(ctypes.c_void_p))()
    br = ctypes.c_size_t(0)
    read_ok = ReadProcessMemory(h_proc, ctypes.c_void_p(base + CInput_OffsetFromModule), ptr_buf, ctypes.sizeof(ctypes.c_void_p), ctypes.byref(br))
    if not read_ok or br.value != ctypes.sizeof(ctypes.c_void_p):
        print(f'Failed to read dwCSGOInput pointer at 0x{(base + CInput_OffsetFromModule):016X}')
        CloseHandle(h_proc)
        return 1
    # unpack pointer (platform-dependent size)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        cinput_ptr = struct.unpack('<Q', bytes(ptr_buf))[0]
    else:
        cinput_ptr = struct.unpack('<I', bytes(ptr_buf))[0]

    if cinput_ptr == 0:
        print('dwCSGOInput pointer is NULL')
        CloseHandle(h_proc)
        return 1

    third_person_addr = cinput_ptr + ThirdPerson_Offset

    q = read_qangle(h_proc, third_person_addr)
    if q is None:
        print(f'Failed to read m_thirdPersonHeading at 0x{third_person_addr:016X}')
        CloseHandle(h_proc)
        return 1

    print('Read m_thirdPersonHeading (QAngle):', q)

    new_q = (q[0], q[1] + 180.0, q[2])
    ok = write_qangle(h_proc, third_person_addr, new_q)
    if not ok:
        print(f'Failed to write new m_thirdPersonHeading at 0x{third_person_addr:016X}')
        CloseHandle(h_proc)
        return 1

    print('Wrote new m_thirdPersonHeading (QAngle).')
    CloseHandle(h_proc)
    return 0


if __name__ == '__main__':
    sys.exit(toggle_third_person_python())
