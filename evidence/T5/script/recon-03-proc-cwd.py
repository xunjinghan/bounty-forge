#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-03: 读取 8095/8091 python 进程的 PEB -> 工作目录，确认实际加载的 app.py 路径。"""
import ctypes
import ctypes.wintypes as wt
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

psapi = ctypes.WinDLL("psapi", use_last_error=True)
psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
psapi.GetModuleFileNameExW.restype = wt.DWORD


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT),
                ("Buffer", ctypes.c_void_p)]


class RTL_USER_PROCESS_PARAMETERS(ctypes.Structure):
    _fields_ = [("Reserved1", ctypes.c_byte * 16),
                ("Reserved2", ctypes.c_void_p * 5),
                ("CurrentDirectoryPath", UNICODE_STRING),
                ("CurrentDirectoryHandle", wt.HANDLE),
                ("DllPath", UNICODE_STRING),
                ("ImagePathName", UNICODE_STRING),
                ("CommandLine", UNICODE_STRING)]


def read_proc_params(pid):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None, f"OpenProcess failed err={ctypes.get_last_error()}"
    try:
        # ImagePathName via psapi (works cross-bitness for exe)
        buf = ctypes.create_unicode_buffer(1024)
        psapi.GetModuleFileNameExW(h, None, buf, 1024)
        exe = buf.value
        # PEB
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [("Reserved1", ctypes.c_void_p),
                        ("PebBaseAddress", ctypes.c_void_p),
                        ("Reserved2", ctypes.c_void_p * 2),
                        ("UniqueProcessId", ctypes.c_void_p),
                        ("Reserved3", ctypes.c_void_p)]
        pbi = PROCESS_BASIC_INFORMATION()
        ret = ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi),
                                              ctypes.sizeof(pbi), None)
        if ret != 0:
            return exe, f"NtQueryInformationProcess ret={ret}"
        peb = pbi.PebBaseAddress
        # PEB->ProcessParameters @ 0x20 on x64
        pp_ptr = ctypes.c_void_p()
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(peb + 0x20),
                                     ctypes.byref(pp_ptr), 8, None):
            return exe, "ReadProcessMemory(PEB+0x20) failed"
        params = RTL_USER_PROCESS_PARAMETERS()
        if not k32.ReadProcessMemory(h, pp_ptr, ctypes.byref(params),
                                     ctypes.sizeof(params), None):
            return exe, "ReadProcessMemory(params) failed"

        def ustr(us):
            if not us.Buffer or not us.Length:
                return ""
            b = ctypes.create_unicode_buffer(us.Length // 2 + 1)
            if not k32.ReadProcessMemory(h, ctypes.c_void_p(us.Buffer), b,
                                         us.Length, None):
                return "<read fail>"
            return b.value

        return exe, {
            "cwd": ustr(params.CurrentDirectoryPath),
            "dllpath": ustr(params.DllPath),
            "image": ustr(params.ImagePathName),
            "cmdline": ustr(params.CommandLine),
        }
    finally:
        k32.CloseHandle(h)


for pid in [5860, 16448]:
    exe, info = read_proc_params(pid)
    print(f"=== PID {pid}")
    print(f"    exe: {exe}")
    if isinstance(info, dict):
        for k, v in info.items():
            print(f"    {k}: {v}")
    else:
        print("    ERR:", info)
