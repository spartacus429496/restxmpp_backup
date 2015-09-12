from callback import Callback
from pycrypt import decode_crypt 
import commands
import logging
import os
from Crypto.PublicKey import RSA
from Crypto import Random
import binascii

class Cmd(Callback):
    def __init__(self):
        self.log = logging.getLogger("cement:app:xmpp")
        self.log.debug('Cmd class creat object !', extra={'namespace' : 'xmpp'})

    def run(self, args = None):
        self.log.debug('args:%s'%args.items(), extra={'namespace' : 'xmpp'})
        cmd = args.get('cmd', 'not found')
        self.log.debug('cmd:%s  '%cmd, extra={'namespace' : 'xmpp'})
        if cmd != 'not found':
            #cmd_decoded = self.decode_crypt(cmd)
            #text = binascii.a2b_hex(data)
            #text = binascii.a2b_hex(cmd)
            #self.log.debug('cmd text:%s  '%text, extra={'namespace' : 'xmpp'})
            #cmd_decoded = decode_crypt(text)
            cmd_decoded = cmd
            self.log.debug('cmd decoded :%s  '%cmd_decoded, extra={'namespace' : 'xmpp'})
            (status, output) = commands.getstatusoutput(cmd_decoded)
            self.log.debug('[status]:%s  [output]:%s'%(status, output), extra={'namespace' : 'xmpp'})
            if status != 0:
                result = 'cmd execute error!'
            else :
                result = output
        return result 

    def ssh_bind(self, args = None):
        """
        ssh -R sourcePort:forwardToHost:onPort connectToHost
        """
        self.log.debug('args:%s'%args.items(), extra={'namespace' : 'xmpp'})
       
        source_port = args.get('source_port', '22')
        on_port = args.get('on_port', '9090')
        connect_to_host = args.get('connect_to_host', 'ibox@www.pinet.cc')
        #path = '/usr/local/src/RestXMPP/bin/'
        path = '/home/spirit/work/git_test/RestXMPP/bin'
        cmd = 'cd %s ; sh ssh_xmpp %s %s %s '%(path, on_port, source_port, connect_to_host) 
        self.log.debug('cmd:%s  '%cmd, extra={'namespace' : 'xmpp'})
        os.system(cmd)
        result = 'OK SSH Tunnel'
        return result 
    """
    def decode_crypt(self,str_src):

        self.log.debug('enter decode ', extra={'namespace' : 'xmpp'})
        home = os.path.expanduser('~')
        self.log.debug('home:%s'%home, extra={'namespace' : 'xmpp'})
        f = open('%s/.ssh/id_rsa'%(home),'r')
        self.log.debug('f:%s'%f, extra={'namespace' : 'xmpp'})
        r = f.read()
        key = RSA.importKey(r)
        self.log.debug('key:%s'%key, extra={'namespace' : 'xmpp'})
        #if key.has_private(): print "Private key"
        s1 = key.decrypt(str_src) 
        print '-' * 30
        print s1
        return s1
    """
    """
    def decode_crypt(str_src):
        home = os.path.expanduser('~')
        f = open('%s/.ssh/id_rsa'%(home),'r')
        r = f.read()
        print r
        key = RSA.importKey(r)
        #if key.has_private(): print "Private key"
        s1 = key.decrypt(str_src) 
        return s1
     """
