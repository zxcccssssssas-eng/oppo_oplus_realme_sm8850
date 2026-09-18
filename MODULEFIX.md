# 6.12.23 modulefix / BTF boot repair

This tree adds a reproducible GitHub Actions build for the bootable modulefix
kernel derived from the Zen/Liquorix 6.12.23 work.

## Included fixes

- `patches/pahole-dwarf-location.patch`
  - upstream dwarves fix for `DW_OP_addrx + DW_OP_plus_uconst`; required so
    pahole generates non-overlapping BTF DATASEC entries for Clang 19 kernels.
- `patches/kernel-modulefix-final.patch`
  - complete source delta from the clean
    `cctv18/android_kernel_common_oneplus_sm8850` 6.12.23 tree to the working
    Zen/Liquorix kernel.
  - includes the reclaim/TCP/Droidspaces/boot fixes, `-O3` + 250 Hz config,
    and the built-in tls / rust_binder / zram / zsmalloc loader shim.
- `zram.zip`
  - the packaged zram KernelSU module now skips `rmmod`/`insmod` when zram is
    built into the kernel.
- `.github/workflows/build-modulefix.yml`
  - installs dependencies, builds patched pahole v1.30, applies the kernel
    patch, builds `Image`, validates the BTF DATASEC entries, applies KPN,
    packages AnyKernel3 and uploads/releases it.

## Trigger

Run the **Build 6.12.23 modulefix kernel** workflow via
`workflow_dispatch`, or run:

```bash
gh workflow run build-modulefix.yml
```
