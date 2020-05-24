#!/usr/bin/python

from pwn import *
import hashlib

#s = process('./')
s = remote('challs.m0lecon.it', 9012)

s.recvuntil('MD5 for ')
string  = s.recvuntil('if')[:-3]
md5     = hashlib.md5(string).hexdigest()
s.recvline()
s.sendline(md5)
s.interactive()
