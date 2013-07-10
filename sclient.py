#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI

import os,sys,time, subprocess
import socket
import base64, cPickle, StringIO
import M2Crypto, struct
from M2Crypto import *


g_prikey_string=\
'''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDnsBbYJcWk7EwP/Oyi6VH83Pl7HhhhXxz8r/d1Y3cCf5omSDI+
UEiIjwxmT5C7lzH2hBnVAgLsqAmMr8O/lLYTYVvwrnQ8XC0Ekg/UW4BsXLcp57QR
VEL7ItjjREWoVQ5zXj+kR+LWDB4yEZYpdXawEkuLtVqT84P13hCpotsjuQIBAwKB
gQCadWSQGS5t8t1f/fMXRjaok1D8vrrrlL39yqT47PoBqmbEMCF+4DBbCghENQsn
uiFPArvjVqydxVuzH9fVDc62USmM6PmQrBHt/Xs8Mkjxb6Hd5yKDMByS6/eY5TpO
lEkxckLIOpm6dWwJavnu4s/btbV6OvqaCQ30KObMx5jnQwJBAP83m/+p6xD14MOx
QI4VxcHpVezdfI3O1LM+3YH0hFf0/ebTNXD5yyA0AnIsGavp+WAOqGzkxEoDSnx2
6rp3L1sCQQDoZgFRU/hJHD7SJbmB/TxzWwcgIs/+SUoNpqBqea4eq6tMCEJ/AnM7
yCF+8yl1VO0hrKvv/eib670kP4u8/pl7AkEAqiUSqnFHYKPrLSDVtA6D1puOnej9
s984d38+VqMC5U3+meIjoKaHas1W9sgRHUamQAnFne3YMVeG/aScfE905wJBAJru
q4uNUDC9fzbD0QFTfaI8r2rB3/7bhrPEavGmdBRycjKwLFSsTNKFa6n3cPjjSMEd
x/VT8GfyfhgqXSipu6cCQQCNmoG9DnSRKr3nIi353mGax841bIYIxtLt4kE5cEm6
LchH9V6aylKm1S3LSDnVPN+eZfY09UTnTh929eNykqpP
-----END RSA PRIVATE KEY-----'''


g_pubkey_string=\
'''-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDnsBbYJcWk7EwP/Oyi6VH83Pl7
HhhhXxz8r/d1Y3cCf5omSDI+UEiIjwxmT5C7lzH2hBnVAgLsqAmMr8O/lLYTYVvw
rnQ8XC0Ekg/UW4BsXLcp57QRVEL7ItjjREWoVQ5zXj+kR+LWDB4yEZYpdXawEkuL
tVqT84P13hCpotsjuQIBAw==
-----END PUBLIC KEY-----'''

g_pubkey = RSA.load_pub_key_bio(BIO.MemoryBuffer(g_pubkey_string))
g_prikey = RSA.load_key_bio(BIO.MemoryBuffer(g_prikey_string))
g_keylen=128#key是1024位也就是128字节，所以每次加密的长度不能超过128-X，所以大数据必须分段加密
#return None(fail) or msg


def pub_encrypt_msg(msg):
    global g_pubkey
    try:
        newmsg=''
        while 1:
            newmsg +=g_pubkey.public_encrypt(msg[0:100], RSA.pkcs1_padding)
            msg=msg[100:]#每段100字节
            if msg=='':
                break
               
        return newmsg
    except:
        print sys.exc_info()
        return None
       
#return None(fail) or msg
def pub_decrypt_msg(msg):
    global g_pubkey, g_keylen
    try:
        newmsg=''
        while 1:
            d=msg[0:g_keylen]
            newmsg +=g_pubkey.public_decrypt(d, RSA.pkcs1_padding)
            msg=msg[g_keylen:]
            if msg=='':
                break
               
        return newmsg
       
    except:
        print sys.exc_info()
        return None

#return None(fail) or msg
def pri_encrypt_msg(msg):
    global g_prikey
    try:
        newmsg=''
        while 1:
            newmsg += g_prikey.private_encrypt(msg[0:100], RSA.pkcs1_padding)
            msg=msg[100:]#每段100字节
            if msg=='':
                break
               
        return newmsg
    except:
        print sys.exc_info()
        return None

#return None(fail) or msg
def pri_decrypt_msg(msg):
    global g_prikey, g_keylen
    try:
        newmsg=''
        while 1:
            d=msg[0:g_keylen]
            newmsg += g_prikey.private_decrypt(d, RSA.pkcs1_padding)
            msg=msg[g_keylen:]
            if msg=='':
                break
               
        return newmsg
    except:
        print sys.exc_info()
        return None

def serialization_data(data):
    return base64.encodestring(cPickle.dumps(data,0))
def deserialization_data(data):
    return cPickle.loads(base64.decodestring(data))

class MyCommonIO(object):
    def __init__(self):
        super(MyCommonIO,self).__init__()
    #return protocol
    def fetch_protocol(self):
        raise Exception('have not defined protocol!')
    #return input data or None(means no input)
    def poll_from_input(self):
        raise Exception('have not defined protocol!')
    #no return value
    def push_to_output(self, data):
        raise Exception('have not defined protocol!')
        
class MySyscmdIO(MyCommonIO):
    def __init__(self, cmd):
        super(MySyscmdIO,self).__init__()
        self.cmd=cmd
    
    def fetch_protocol(self):
        return ['exec-syscmd', len(self.cmd)]
    
    def poll_from_input(self):
        data=self.cmd
        self.cmd=None
        return data
        
    def push_to_output(self, data):
        print data
        
class MyUploadFileIO(MyCommonIO):
    def __init__(self, localfile_or_data, remotefile, by_file):
        super(MyUploadFileIO,self).__init__()
        self.remotefile=remotefile
        
        if by_file:
            self.fd=open(localfile_or_data, 'rb')
            self.data=None
            self.datasize=os.path.getsize(localfile_or_data)
        else:
            self.fd=None
            self.data=localfile_or_data
            self.datasize=len(localfile_or_data)
            
    def __del__(self):
        if self.fd:
            self.fd.close()
    
    def fetch_protocol(self):
        return ['uploadfile', self.remotefile, self.datasize]
    
    def poll_from_input(self):
        if self.fd:
            readsize=1024*64
            data=self.fd.read(readsize)
        else:
            data=self.data
            self.data=None
        return data
    
    def push_to_output(self, data):
        print data
        
class MyDownloadFileIO(MyCommonIO):
    def __init__(self, localfile_or_data, remotefile):
        super(MyDownloadFileIO,self).__init__()
        self.remotefile=remotefile
        
        if localfile_or_data:
            self.fd=open(localfile_or_data, 'wb+')
            self.output_io=self.fd
        else:
            self.fd=None
            self.output_io=sys.stdout

    def __del__(self):
        if self.fd:
            self.fd.close()

    def fetch_protocol(self):
        return ['downloadfile', self.remotefile]
    
    #no input value
    def poll_from_input(self):
        return None
    
    def push_to_output(self, data):
        self.output_io.write(data)

class MyPythonIO(object):
    def __init__(self, pythonfile_or_data, by_file):
        super(MyPythonIO,self).__init__()
        if by_file:
            fd=open(pythonfile_or_data, 'rb')
            self.data=fd.read()
            fd.close()
        else:
            self.data=pythonfile_or_data
        
    
    def fetch_protocol(self):
        return ['exec-python', len(self.data)]
    
    def poll_from_input(self):
        data=self.data
        self.data=None
        return data   
    
    def push_to_output(self, data):
        print data


def send_data(one_io):
    global g_connect_addr
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    data=''
    try:
        connect_success=0
        sock.connect(g_connect_addr)
        connect_success=1
        packsize=1024*8
        protocol=one_io.fetch_protocol()
        protocol=serialization_data(protocol)
        protocol=pri_encrypt_msg(protocol)
        headsize=struct.pack("i", len(protocol))
        sock.send(headsize+protocol)
        #============send data============
        while 1:
            data=one_io.poll_from_input()
            if not data:
                break #no input
            sock.send(data)

        #============recv data============
        recvsize = sock.recv(4)
        recvsize=struct.unpack("i", recvsize)[0]
        while recvsize:
            data=sock.recv(packsize)
            if len(data)==0:
                print 'over'
                break
            recvsize-=len(data)
            one_io.push_to_output(data)
        
    except Exception,e:
        print e
    finally:
        if connect_success:
            sock.close()
    

default_template=\
'''
import os,sys,time,subprocess
print time.ctime()
'''

cmd_template=\
'''
import os,sys,time,subprocess
try:
    p=subprocess.Popen('%s',shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child_stdin,child_stdout,child_stderr = p.stdin, p.stdout, p.stderr
    print child_stdout.read()
except:
    print sys.exc_info()
'''


def exec_cmd(cmd):
    s=cmd_template % cmd
    one_io=MySyscmdIO(s)
    send_data(one_io)
 
def write_file(localfile_or_data, remotefile, by_file):
    one_io=MyUploadFileIO(localfile_or_data, remotefile, by_file)
    send_data(one_io)

def read_file(localfile, remotefile):
    one_io=MyDownloadFileIO(localfile, remotefile)
    send_data(one_io)

def exec_python(pythonfile_or_data, by_file):
    one_io=MyPythonIO(pythonfile_or_data, by_file)
    send_data(one_io)

def usage():
    print '%s usage:' % sys.argv[0]
    print '\t ip -e cmd                                  #exec system cmd'
    print '\t ip -r remotefile [localfile=stdout]        #read file'
    print '\t ip -w remotefile "haha"                    #write file'
    print '\t ip -wf remotefile localfile                #write file'
    print '\t ip -p "print 123"                          #exec python script!'
    print '\t ip -pf localfile(1.py)                     #exec python script file!'

from optparse import OptionParser
parser=OptionParser()
    
if __name__=='__main__':
    try:
        if len(sys.argv)<3:
            usage()
            sys.exit(0)

        g_connect_addr=(sys.argv[1],22000)
        a=2
        socket.setdefaulttimeout(3)
        if sys.argv[a]=='-e':
            cmd=' '.join(sys.argv[a+1:])
            exec_cmd(cmd)

        elif sys.argv[a]=='-r':
            localfile=''
            remotefile=sys.argv[a+1]
            if len(sys.argv)>a+2:
                localfile=sys.argv[a+2]
            read_file(localfile, remotefile)

        elif sys.argv[a]=='-w':
            remotefile=sys.argv[a+1]
            data=' '.join(sys.argv[a+2:])
            write_file(data, remotefile, False)

        elif sys.argv[a]=='-wf':
            remotefile=sys.argv[a+1]
            localfile=sys.argv[a+2]
            write_file(localfile, remotefile, True)

        elif sys.argv[a]=='-p':
            pythonfile_or_data=default_template
            pythonfile_or_data=sys.argv[a+1]
            exec_python(pythonfile_or_data, False)

        elif sys.argv[a]=='-pf':
            pythonfile_or_data=sys.argv[a+1]
            exec_python(pythonfile_or_data, True)

        else:
            usage()
    except Exception, error:
        print error
    sys.exit(0)
