#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI

import os,sys,time
import SocketServer, socket
import base64, cPickle
import StringIO, struct

import M2Crypto
from M2Crypto import *


g_pubkey_string=\
'''-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDnsBbYJcWk7EwP/Oyi6VH83Pl7
HhhhXxz8r/d1Y3cCf5omSDI+UEiIjwxmT5C7lzH2hBnVAgLsqAmMr8O/lLYTYVvw
rnQ8XC0Ekg/UW4BsXLcp57QRVEL7ItjjREWoVQ5zXj+kR+LWDB4yEZYpdXawEkuL
tVqT84P13hCpotsjuQIBAw==
-----END PUBLIC KEY-----'''
g_pubkey = RSA.load_pub_key_bio(BIO.MemoryBuffer(g_pubkey_string))
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

def serialization_data(data):
    return base64.encodestring(cPickle.dumps(data,0))
def deserialization_data(data):
    return cPickle.loads(base64.decodestring(data))

g_running=1
class MyRequestHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        print 'connected from',self.client_address
        oldstdout=sys.stdout
        packsize=1024*8
        fd=None
        try:
            data=''
            headsize=self.request.recv(4)
            headsize=struct.unpack("i", headsize)[0]

            protocol=self.request.recv(headsize)
            protocol=pub_decrypt_msg(protocol)
            protocol=deserialization_data(protocol)
                
            if  protocol[0]=='exec-syscmd' or protocol[0]=='exec-python':
                print protocol[0],':'
                recvsize=protocol[1]
                while recvsize!=0:
                    ret=self.request.recv(packsize)
                    if len(ret)==0:
                        break
                    recvsize-=len(ret)
                    data+=ret
                print data
                myio=StringIO.StringIO()
                sys.stdout=myio#self.wfile
                exec data in locals()
                sys.stdout=oldstdout
                data=myio.getvalue()
                datasize = struct.pack("i", len(data))
                #print 'send datasize:',len(data) 
                self.request.sendall(datasize+data)
                myio.close()
                
            elif protocol[0]=='uploadfile':
                print protocol[0]
                self.remotefile=protocol[1]
                recvsize=protocol[2]
                fd=open(self.remotefile, 'wb+')
                while recvsize:
                    ret=self.request.recv(packsize)
                    if len(ret)==0:
                        break
                    recvsize-=len(ret)
                    fd.write(ret)
                
                datasize = struct.pack("i", 0)
                self.request.send(datasize)
                
            elif protocol[0]=='downloadfile':
                print protocol[0]
                self.remotefile=protocol[1]
                
                datasize = struct.pack("i", os.path.getsize(self.remotefile))
                print 'send datasize:',os.path.getsize(self.remotefile) 
                self.request.send(datasize)
                
                fd=open(self.remotefile, 'rb')
                while 1:
                    ret=fd.read(packsize)
                    if len(ret)==0:
                        break
                    self.request.send(ret)
            else:
                self.request.send('invalid protocol')

        except:
            print sys.exc_info()
        finally:
            sys.stdout=oldstdout
            if fd:
                fd.close()

        print self.client_address,'disconnect'
                    
if __name__=='__main__':
    socket.setdefaulttimeout(10)
    port=22000
    server = SocketServer.ThreadingTCPServer(('0.0.0.0',port),MyRequestHandler)
    print 'start listen port:',port
    try:
        server.serve_forever()
    except KeyboardInterrupt,e:
        print 'bye'
        g_running=0
        sys.exit(0)
