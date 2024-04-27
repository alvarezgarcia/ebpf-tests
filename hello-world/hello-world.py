#!/usr/bin/python

from bcc import BPF

def main():
    with open("hello-world.bpf.c", "r") as f:
        bpf_program = f.read()

    b = BPF(text=bpf_program)
    syscall_name = "chmod"

    syscall = b.get_syscall_prefix().decode() + syscall_name

    b.attach_kprobe(event=syscall, fn_name="syscall")
    b.trace_print()

if __name__ == "__main__":
    main()
