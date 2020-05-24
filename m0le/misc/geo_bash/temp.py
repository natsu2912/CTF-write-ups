#!/usr/bin/python3

from pwn import *
import pickle
with open('../../hashtable', 'rb') as dict_file:
    mapper = pickle.load(dict_file)
while True:
    s = remote('challs.m0lecon.it', 10001)
    inp_ = s.recv(1024).decode().strip()
    print(inp_)
    hash_ = inp_.strip('.').rsplit(' ', 1)[1]
    s.sendline(mapper[hash_])
    inp_ = s.recv(1024).decode().strip()
    print(inp_)
    if 'PoW' not in inp_:
        break

s.interactive()
