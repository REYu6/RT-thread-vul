# Vulnerability 4: finsh TAB-Completion Heap Out-of-Bounds Write

Issue: [RT-Thread/rt-thread#11738](https://github.com/RT-Thread/rt-thread/issues/11738)
Target: RT-Thread master `6ea6827`, bsp/qemu-vexpress-a9, default configuration
Repro: `qemu-system-arm -M vexpress-a9 -kernel rtthread.elf -sd sd.bin -nographic`

## Description

`msh_auto_complete_path()` in `components/finsh/msh.c` copies the
completion result into `shell->line` (`char line[FINSH_CMD_SIZE + 1]` =
257 bytes, embedded in the heap-allocated `struct finsh_shell`) without
ever checking that it fits:

```c
length = index - path;
rt_memcpy(index, full_path, min_length);   /* min_length unclamped: from the dirent name, up to 255 */
path[length + min_length] = '\0';
```

`min_length` originates from the filesystem entry name (LFN up to 255
characters) while the typed prefix can itself be up to 256 characters, and
nothing bounds `length + min_length`. Additionally, the prefix-fill loop
into `full_path = rt_malloc(256)` (:640, loop at :667-672) is unbounded,
and `getcwd()` does not NUL-terminate on truncation (`dfs_posix.c:1373`,
`rt_strncpy` semantics), causing an out-of-bounds read before the write.
Triggered by a single TAB key press on the serial console; the overflowing
bytes come from an attacker-created filename. On no-MMU builds this is
kernel heap corruption.

Reproduced result: `echo ` + a 200-character prefix + TAB (with a
184-character filename at the filesystem root): 390 bytes were written,
**133 bytes past the end of `line[257]`**, and the 205-character input
line was physically destroyed into `echo L`.

## Screenshot

![TAB completion heap overflow](https://raw.githubusercontent.com/REYu6/rt-thread-poc-evidence/main/tab.png)

## PoC

Prepare the long-named file on the host (once):

```bash
python3 -c "open('L'*180+'.txt','w').write('X'*16)"
mcopy -i sd.bin L*.txt ::/
```

Boot, then at the msh console type (finish with the TAB key):

```
msh />echo LLLL…(200 consecutive L characters)[TAB]
msh />echo L          ← the original input line has been destroyed by the completion write
```
