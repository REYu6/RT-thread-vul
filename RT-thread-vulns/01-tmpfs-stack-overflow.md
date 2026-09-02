# Vulnerability 1: tmpfs Path-Component Stack Buffer Overflow

Issue: [RT-Thread/rt-thread#11735](https://github.com/RT-Thread/rt-thread/issues/11735)
Target: RT-Thread master `6ea6827`, bsp/qemu-vexpress-a9, default configuration
Repro: `qemu-system-arm -M vexpress-a9 -kernel rtthread.elf -sd sd.bin -nographic`

## Description

`components/dfs/dfs_v2/filesystems/tmpfs/dfs_tmpfs.c` copies arbitrarily long
path components into 32-byte stack buffers in two places, with no length
check:

- `_path_separate()` (dfs_tmpfs.c:71):
  `rt_memcpy(file_name, path_p, path_q - path_p)` writes into
  `char file_name[TMPFS_NAME_MAX = 32]`; reached from the `mkdir`/`rename` paths;
- `_get_subdir()` inside `dfs_tmpfs_lookup()` (:86-98, :258-259): a
  byte-by-byte copy loop into `char subdir_name[32]`, triggered by ANY
  `open`/`stat` — file creation is not required.

A path component longer than 32 characters overwrites the stack frame
(saved registers and the return address) with fully attacker-controlled
bytes and length. Reachable from the serial console (mkdir is an exported
command), from msh scripts on mounted media, or from any application that
passes externally derived filenames to POSIX calls. On no-MMU builds this
is device takeover / permanent crash; under `RT_USING_SMART` it is a
user-application → kernel escalation.

Reproduced result: `/poc.sh` (a single `mkdir` with a 72-character
component) → **data abort**; the backtrace shows the return address slot
overwritten with `0x41414141`; the faulting PC resolves to
`dfs_tmpfs_lookup`, dfs_tmpfs.c:263.

## Screenshot

![tmpfs stack overflow](https://raw.githubusercontent.com/REYu6/rt-thread-poc-evidence/main/tmpfs.png)

## PoC

Place `poc.sh` on the SD card (msh script) and run `/poc.sh` from the console:

```sh
mkdir /tmp
poc_mount
mkdir /tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

`poc_mount` is a one-line exported command (any in-firmware application
mounting tmpfs serves the same purpose):

```c
static void poc_mount(int argc, char **argv)
{
    dfs_mount(RT_NULL, "/tmp", "tmp", 0, RT_NULL);
}
MSH_CMD_EXPORT(poc_mount, mount tmpfs at /tmp);
```
