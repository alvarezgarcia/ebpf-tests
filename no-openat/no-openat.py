#!/usr/bin/python

import sys

from bcc import BPF
import ctypes as ct

def main():
    with open("no-openat.bpf.c", "r") as f:
        bpf_program = f.read()

    b = BPF(text=bpf_program)
    syscall = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=syscall, fn_name="syscall__openat")

    file_to_protect = sys.argv[1]

    files = b.get_table("files")
    key = files.Key()
    key.name = file_to_protect.encode()
    value = ct.c_int(1)
    files[key] = value

    b.trace_print()

if __name__ == "__main__":
    main()
