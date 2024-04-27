#!/usr/bin/python

import sys

from bcc import BPF
import ctypes as ct

def main():
    with open("no-ping.bpf.c", "r") as f:
        bpf_program = f.read()

    b = BPF(text=bpf_program)
    BPF.attach_xdp(dev="enp0s5", fn=b.load_func("xdp_no_ping", BPF.XDP), flags = BPF.XDP_FLAGS_SKB_MODE)

    try:
        print("Running...")
        b.trace_print()
    except KeyboardInterrupt:
        pass

    b.remove_xdp("enp0s5")

if __name__ == "__main__":
    main()
