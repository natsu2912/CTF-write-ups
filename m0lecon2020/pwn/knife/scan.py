#!/usr/bin/python
def scan():
    port = 2000
    while True:
        try:
            log.info('PORT: ' + str(port))
            if DEBUG:
                s = remote('localhost', str(port))
            else:
                s = remote('challs.m0lecon.it', 9010)
            s.sendline('a')
            s.close()
            log.critical('PORT: ' + str(port))
            break
        except EOFError:
            port += 1
            s.close()
            continue
    return port


from pwn import *
port = 1000
while True:
    try:
        log.info('PORT: ' + str(port))
        s = process(['nc', '0', str(port)])
        s.sendline('a')
        exit()
    except EOFError:
        port += 1
        s.close()
        continue
