#!/usr/bin/python

from pwn import *

context.log_level = 'debug'
s = remote('challs.m0lecon.it', 10000)

s.recvuntil('You have 1 second for each of the 10 tests.\n')
for i in range(10):
    s.recvuntil('N = ')
    n = int(s.recvline(False), 10)
    s.sendline(str(n-1) + " 1")
s.interactive()
