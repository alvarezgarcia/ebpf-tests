#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct {
	char name[256];
} Files;

BPF_HASH(files, Files, int);
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
	Files key = {};

	bpf_probe_read_user_str(&key.name, sizeof(key.name), (void *)filename);
	int *found = files.lookup(&key);

	if (found != NULL && *found == 1) {
		bpf_trace_printk("Not allowed to open %s\n", key.name);
		bpf_send_signal(9);
	}

	return 0;
}
