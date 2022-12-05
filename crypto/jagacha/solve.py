from pwn import *
from randcrack import RandCrack

conn = remote('xxx', 32526)
conn.recvuntil(b'3. Exit\n')

rc = RandCrack()

for i in range(312):
    conn.sendline(b'1')
    conn.recvuntil(b"Here are the stats of your character:\n")
    rand_val = 0
    for j in range(2):
        rand_val <<= 16
        val = conn.recvuntil(b"\n")
        rand_val |= int(val.decode().split(": ")[1].strip())
    
    rand_val2 = 0
    for j in range(2):
        rand_val2 <<= 16
        val = conn.recvuntil(b"\n")
        rand_val2 |= int(val.decode().split(": ")[1].strip())
    rc.submit(rand_val2)
    rc.submit(rand_val)
    conn.recv()

conn.sendline(b'2')
num = rc.predict_getrandbits(64)
print(conn.recv())
conn.sendline(str(num).encode())
print(conn.recv())
conn.sendline(b'3')
print(conn.recvall())