/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * kpm-bwrap-userns — KernelPatch-Next Module (KPM)
 *
 * Allow Termux (and any app process) to run bubblewrap-style sandboxes on
 * Android by permitting the user/mount namespace related syscalls in the
 * seccomp filter applied by zygote.
 *
 * This version never fails in init: it records status and exposes it via
 * KPM_CTL0 so loading failures can be diagnosed with:
 *   kpatch kpm ctl0 kpm-bwrap-userns get
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include <kputils.h>

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
static unsigned long proc_sys_permission_addr;
static long hook_status;
static char status_msg[128];

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


/* MAY_READ = 4；只放开 /proc/sys 的读权限（bwrap 需要读 overflowuid），写权限仍走原检查 */
#define KPM_MAY_READ 4

static void before_proc_sys_permission(hook_fargs3_t *args, void *udata)
{
	if ((args->arg2 & KPM_MAY_READ) != 0) {
		args->skip_origin = 1;
		args->ret = 0; /* allow read */
		logkd("kpm-bwrap-userns: allow proc_sys read\n");
	}
}
static long kpm_init(const char *args, const char *event, void *__user reserved)
{
	hook_status = 0;
	strcpy(status_msg, "init");

	secure_computing_addr = kallsyms_lookup_name("__secure_computing");
	if (!secure_computing_addr) {
		hook_status = -1;
		strcpy(status_msg, "KALLSYMS_NOT_FOUND");
		logkd("kpm-bwrap-userns: KALLSYMS_NOT_FOUND\n");
		return 0;
	}

	hook_err_t err = hook_wrap((void *)secure_computing_addr, 1,
				   before_secure_computing, NULL, NULL);
	hook_status = (long)err;
	if (err == HOOK_NO_ERR) {
		strcpy(status_msg, "HOOKED");
	} else {
		strcpy(status_msg, "HOOK_ERR");
	}
	logkd("kpm-bwrap-userns: addr=%px hook_err=%d\n",
	      (void *)secure_computing_addr, err);

	proc_sys_permission_addr = kallsyms_lookup_name("proc_sys_permission");
	if (proc_sys_permission_addr) {
		hook_err_t err2 = hook_wrap((void *)proc_sys_permission_addr, 3,
					    before_proc_sys_permission, NULL, NULL);
		if (err2 == HOOK_NO_ERR) {
			strcat(status_msg, "+PROCSYS_OK");
		} else {
			strcat(status_msg, "+PROCSYS_ERR");
		}
		logkd("kpm-bwrap-userns: proc_sys_permission addr=%px hook_err=%d\n",
		      (void *)proc_sys_permission_addr, err2);
	} else {
		strcat(status_msg, "+PROCSYS_NF");
		logkd("kpm-bwrap-userns: proc_sys_permission not found\n");
	}
	return 0;
}

static long kpm_ctl0(const char *args, char *__user out_msg, int outlen)
{
	char buf[160];
	strcpy(buf, "status=");
	strcat(buf, status_msg);
	compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
	return 0;
}

static long kpm_exit(void *__user reserved)
{
	if (secure_computing_addr)
		unhook((void *)secure_computing_addr);
	if (proc_sys_permission_addr)
		unhook((void *)proc_sys_permission_addr);
	return 0;
}

KPM_INIT(kpm_init);
KPM_CTL0(kpm_ctl0);
KPM_EXIT(kpm_exit);
