# kpm-bwrap-userns

KernelPatch Module (KPM)：让 Android 上 Termux 的 bubblewrap 沙箱能工作。

## 问题

Android zygote 会给 `untrusted_app`（Termux 属于此类）应用一层 **seccomp 白名单**，
禁止 `unshare(CLONE_NEWUSER)`、`setns`、`mount`、`pivot_root` 等系统调用。
bubblewrap 需要这些调用来创建 user+mount namespace 沙箱，所以 dsh / bwrap 在 Termux 上直接失败：

```
bwrap: Creating new namespace failed, likely because the kernel does not support user namespaces.
```

## 原理

本模块 inline-hook 内核函数 `__secure_computing()`：
- 当 seccomp 过滤器询问以下 syscall 时，直接返回“允许”（跳过原过滤器）：
  - `mount` (40) / `umount2` (39) / `pivot_root` (41) / `chroot` (161)
  - `unshare` (272) / `setns` (268)
- 其余 syscall 完全走原逻辑，不做任何改动。

> 注意：当前是**全局放行**（所有 app 进程），后续可以按 Termux uid (10336)
> 精确过滤。自用内核可接受，刷给他人请谨慎。

## 编译

需要：
- Android NDK（或任意能产出 `aarch64-linux-android31` target 的 clang）
- KernelPatch 源码树：`git clone --depth=1 https://github.com/bmax121/KernelPatch.git ~/KernelPatch`

```bash
export NDK_PATH=/path/to/android-ndk
export KP_DIR=$HOME/KernelPatch   # 默认 ../../../KernelPatch
make
```

产物：`termux_bwrap_userns.kpm`

### Termux 本地编译（无 NDK 时）

Termux 自带 clang 支持 android target：

```bash
export KP_DIR=$HOME/KernelPatch
clang --target=aarch64-linux-android31 \
  -I$KP_DIR/kernel/include -I$KP_DIR/kernel/patch/include \
  -I$KP_DIR/kernel/linux/include -I$KP_DIR/kernel/linux/arch/arm64/include \
  -I$KP_DIR/kernel/linux/tools/arch/arm64/include \
  -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector \
  -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE \
  -fno-common -fvisibility=hidden \
  -Ttermux_bwrap_userns.lds -c -O2 -o termux_bwrap_userns.o termux_bwrap_userns.c
clang --target=aarch64-linux-android31 -r -s -o termux_bwrap_userns.kpm termux_bwrap_userns.o
llvm-strip -g --strip-unneeded --strip-debug \
  --remove-section=.comment --remove-section=.note.GNU-stack termux_bwrap_userns.kpm
```

## 加载

- APatch / KernelPatch：APatch Manager → KPM → 加载 `termux_bwrap_userns.kpm`
- 本仓库内核编译时启用 KPM（`USE_PATCH_LINUX=b` 或 `k`）后，也可在开机后加载

## 验证

```bash
# Termux 里（加载 KPM 后）
bwrap --ro-bind / / --dev /dev --proc /proc --die-with-parent -- true
```

如果不再报 `Creating new namespace failed`，说明 seccomp 已放行。
