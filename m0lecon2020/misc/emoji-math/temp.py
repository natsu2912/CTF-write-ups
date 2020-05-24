#!/usr/bin/python

from pwn import *
import hashlib

#context.log_level = 'debug'
#s = process('./')
s = remote('challs.m0lecon.it', 10002)

s.recvuntil('MD5 for ')
string  = s.recvuntil('if')[:-3]
md5     = hashlib.md5(string).hexdigest()
s.recvline()
s.sendline(md5)
s.interactive()
