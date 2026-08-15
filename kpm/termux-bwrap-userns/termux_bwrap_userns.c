/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * kpm-bwrap-userns — KernelPatch Module (KPM)
 *
 * Allow Termux (and any app process) to run bubblewrap-style sandboxes on
 * Android by permitting the user/mount namespace related syscalls in the
 * seccomp filter applied by zygote.
 *
 * Why: Android's zygote applies a seccomp allowlist to untrusted_app
 * processes that blocks unshare(CLONE_NEWUSER), setns, mount, pivot_root,
 * etc.  bubblewrap needs those to create a user+mount namespace sandbox.
 * This module inline-hooks __secure_computing() and returns "allowed" for
 * exactly the syscalls bubblewrap needs, leaving everything else untouched.
 *
 * Build: see README.md (KPM-Build-Anywhere style, no kernel source needed).
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/printk.h>

KPM_NAME("kpm-bwrap-userns");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("cctv18");
KPM_DESCRIPTION("Allow user/mount namespace syscalls for bubblewrap on Android");

/* Minimal view of struct seccomp_data (we only need the syscall number). */
struct kpm_seccomp_data {
	int nr;
	/* __u32 arch; __u64 instruction_pointer; __u64 args[6]; ... */
};

/* arm64 syscall numbers used by bubblewrap */
#define __NR_arm64_mount       40
#define __NR_arm64_umount2     39
#define __NR_arm64_pivot_root  41
#define __NR_arm64_chroot      161
#define __NR_arm64_unshare     272
#define __NR_arm64_setns       268

static unsigned long secure_computing_addr;

static void before_secure_computing(hook_fargs1_t *args, void *udata)
{
	const struct kpm_seccomp_data *sd =
		(const struct kpm_seccomp_data *)args->arg0;

	if (!sd)
		return;

	switch (sd->nr) {
	case __NR_arm64_mount:
	case __NR_arm64_umount2:
	case __NR_arm64_pivot_root:
	case __NR_arm64_chroot:
	case __NR_arm64_unshare:
	case __NR_arm64_setns:
		args->skip_origin = 1;
		args->ret = 0; /* allow */
		logkd("kpm-bwrap-userns: allowed syscall %d\n", sd->nr);
		break;
	default:
		break;
	}
}

static long kpm_init(const char *args, const char *event, void *__user reserved)
{
	secure_computing_addr = kallsyms_lookup_name("__secure_computing");
	if (!secure_computing_addr) {
		pr_err("kpm-bwrap-userns: __secure_computing not found\n");
		return -1;
	}

	hook_err_t err = hook_wrap((void *)secure_computing_addr, 1,
				   before_secure_computing, NULL, NULL);
	if (err != HOOK_NO_ERR) {
		pr_err("kpm-bwrap-userns: hook __secure_computing failed: %d\n", err);
		return -1;
	}

	logkd("kpm-bwrap-userns: hooked __secure_computing at %px\n",
	      (void *)secure_computing_addr);
	return 0;
}

static long kpm_exit(void *__user reserved)
{
	if (secure_computing_addr)
		unhook((void *)secure_computing_addr);
	return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);
