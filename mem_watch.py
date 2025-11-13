"""
Memory watcher to help locate a boolean/flag that changes when you toggle third-person.
Usage: run while CS2 is running. It will read a range of memory around
base + dwCSGOInput + 0x2400..0x25FF (configurable), wait for you to toggle the view,
then read again and show addresses that changed (byte/word/dword/float views).

This script prefers pyMeow (imported as pm). If not available, it falls back to ctypes WinAPI.

Be careful: this script reads memory only (non-destructive).
"""

import struct
import time
import ctypes
from ctypes import wintypes

# config
CInput_OffsetFromModule = 0x1E28800
ThirdPerson_Offset = 0x24F0
RANGE_START = 0x2300  # relative to CInput (covers 0x2400..0x25FF when combined with ThirdPerson_Offset)
RANGE_END = 0x2600

USE_PYMEOW = False
pm = None
try:
    import pyMeow as pm
    USE_PYMEOW = True
except Exception:
    USE_PYMEOW = False

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
CloseHandle = Kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


def get_pid(name='cs2.exe'):
    if USE_PYMEOW:
        try:
            for p in pm.processes():
                if p.name.lower() == name.lower():
                    return p.pid
        except Exception:
            pass

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value:
        return 0
    if not Process32First(snap, ctypes.byref(pe)):
        CloseHandle(snap)
        return 0
    while True:
        if pe.szExeFile.lower() == name.lower():
            pid = pe.th32ProcessID
            CloseHandle(snap)
            return pid
        if not Process32Next(snap, ctypes.byref(pe)):
            break
    CloseHandle(snap)
    return 0


def get_module_base(pid, mod='client.dll'):
    if USE_PYMEOW:
        try:
            for m in pm.modules(pid):
                if m.name.lower() == mod.lower():
                    return m.base
        except Exception:
            pass

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == wintypes.HANDLE(-1).value:
        return 0
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(me)
    if not Module32FirstW(snap, ctypes.byref(me)):
        CloseHandle(snap)
        return 0
    while True:
        if me.szModule.lower() == mod.lower():
            base = me.modBaseAddr
            CloseHandle(snap)
            return base
        if not Module32NextW(snap, ctypes.byref(me)):
            break
    CloseHandle(snap)
    return 0


def read_bytes(h, addr, size):
    buf = (ctypes.c_ubyte * size)()
    br = ctypes.c_size_t(0)
    ok = ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(br))
    if not ok or br.value != size:
        return None
    return bytes(buf[:size])


def snapshot_range(h, base, rel_start, rel_end):
    # read dwCSGOInput pointer
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    ptr_buf = (ctypes.c_ubyte * ptr_size)()
    br = ctypes.c_size_t(0)
    ok = ReadProcessMemory(h, ctypes.c_void_p(base + CInput_OffsetFromModule), ptr_buf, ptr_size, ctypes.byref(br))
    if not ok or br.value != ptr_size:
        return (0, None)
    if ptr_size == 8:
        cinput_ptr = struct.unpack('<Q', bytes(ptr_buf))[0]
    else:
        cinput_ptr = struct.unpack('<I', bytes(ptr_buf))[0]

    start = cinput_ptr + rel_start
    end = cinput_ptr + rel_end
    size = end - start
    data = read_bytes(h, start, size)
    return (start, data)


def compare_snapshots(s1, s2):
    start, d1 = s1
    _, d2 = s2
    if d1 is None or d2 is None:
        print('Failed to read one of the snapshots')
        return []
    changes = []
    for i in range(min(len(d1), len(d2))):
        if d1[i] != d2[i]:
            addr = start + i
            b1 = d1[i]
            b2 = d2[i]
            # also show dword and float at aligned addresses
            aligned = addr & ~0x3
            # read dword/float from d1/d2 if within range
            def read_u32(data, off):
                if off+4 <= len(data):
                    return struct.unpack_from('<I', data, off)[0]
                return None
            def read_f32(data, off):
                if off+4 <= len(data):
                    return struct.unpack_from('<f', data, off)[0]
                return None
            off = i
            dword1 = read_u32(d1, off- (off%4))
            dword2 = read_u32(d2, off- (off%4))
            float1 = read_f32(d1, off- (off%4))
            float2 = read_f32(d2, off- (off%4))
            changes.append((addr, b1, b2, dword1, dword2, float1, float2))
    return changes


def main():
    pid = get_pid()
    if pid == 0:
        print('cs2.exe not found')
        return 1
    h = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print('Failed to open process')
        return 1
    base = get_module_base(pid)
    if base == 0:
        print('Failed to get client.dll base')
        CloseHandle(h)
        return 1
    print(f'PID={pid}, client.dll base=0x{base:016X}')
    print(f'Reading range +{RANGE_START:03X} .. +{RANGE_END:03X} relative to CInput')
    input('Position the game and press Enter to take the first snapshot (read-only)...')
    s1 = snapshot_range(h, base, RANGE_START, RANGE_END)
    print('First snapshot taken. Now toggle third-person in-game, then press Enter to take second snapshot.')
    input('Press Enter after toggling...')
    s2 = snapshot_range(h, base, RANGE_START, RANGE_END)
    changes = compare_snapshots(s1, s2)
    if not changes:
        print('No changes detected in the range')
    else:
        print('Detected changes:')
        for c in changes:
            addr, b1, b2, d1, d2, f1, f2 = c
            print(f'0x{addr:016X}: {b1:#04x} -> {b2:#04x}', end='')
            if d1 is not None and d2 is not None:
                print(f', dword: {d1:#010x} -> {d2:#010x}', end='')
            if f1 is not None and f2 is not None:
                print(f', float: {f1:.6g} -> {f2:.6g}', end='')
            print()
    CloseHandle(h)
    return 0

if __name__ == '__main__':
    main()
