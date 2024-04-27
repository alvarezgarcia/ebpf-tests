int syscall(void *ctx) {
	bpf_trace_printk("Hello World!");
	return 0;
}
