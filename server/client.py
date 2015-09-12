#===============================================================================
#
# The XMPP Client
# 
# @version 1.0
# @author Jack <guitarpoet@gmail.com>
# @date Tue May  5 15:57:03 2015
#
#===============================================================================

# Imports
from sleekxmpp import ClientXMPP
from sleekxmpp.exceptions import IqError, IqTimeout
from callback_hdl import callback_handle
import ssl
import logging
import json

from pycrypt import encode_crypt, decode_crypt 
import binascii
import m2c_crypt_sign as m2c

class Client(ClientXMPP):

    class Meta:
        label = 'client'

    """
    The XMPP Client
    """
    
    def __init__(self, jid, password, server, server_port, friend_pattern, group, room, nick):
        """
        The constructor of the XMPP Client
        """

        ClientXMPP.__init__(self, jid, password)
        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler("message", self.message, threaded=True)
        self.add_event_handler('presence_subscribe',
                               self.subscribe)
        self._password = password
        self._server = server
        self._server_port = server_port
        self._friend_pattern= friend_pattern 
        self._friend_default_group = group 
        self._connection = None
        self._auth = None
        self.loggedin = False
        self.joinmuc = False
        self._log = logging.getLogger("cement:app:xmpp")
        self.ssl_version = ssl.PROTOCOL_SSLv3
        self._log.info('XMPP client initialized...', extra={'namespace' : 'xmpp'})
        if self._server_port != 5222:
            self._log.info('server_port:%s is not default value!'%(self._server_port), extra={'namespace' : 'xmpp'})
        
        self.register_plugin('xep_0030') # Service Discovery
        self.register_plugin('xep_0045') # Multi-User Chat
        self.register_plugin('xep_0199') # XMPP Ping
        #Adapt the value of self.room when you test the conference
        self.room = room 
        self.nick = nick 

    def session_start(self, event):
        self.send_presence()
        try:
            self.get_roster()
            self._log.info('Now sending the message...', extra={'namespace' : 'xmpp'})
        except IqError as err:
            self._log.error('There was an error getting the roster')
            self._log.error(err.iq['error']['condition'])
            self.disconnect()
        except IqTimeout:
            self._log.error('Server is taking too long to respond')
            self.disconnect()

    def message(self, msg):
        """
        Process incoming message stanzas. Be aware that this also
        includes MUC messages and error messages. It is usually
        a good idea to check the messages's type before processing
        or sending replies.
        Arguments:
            msg -- The received message stanza. See the documentation
                   for stanza objects and the Message stanza to see
                   how it may be used.
        """
        if msg['type'] in ('chat', 'normal'):
            self.analysis_msg(msg)

        elif msg['type'] == 'groupchat':
            self._log.info('Receive groupchat message:%s' %msg, extra={'namespace' : 'xmpp'})
            if msg['mucnick'] != self.nick:
                self.analysis_msg(msg)

        return 

    def analysis_msg(self,msg):
        #msg_decode = msg['body'].decode('utf-8')
        msg_context = msg['body']

        self._log.debug('Receive msg:%s' %msg_context, extra={'namespace' : 'xmpp'})
        msg_ret = {}
        #bin to ascii
        #encoded_str= binascii.a2b_hex(msg['body'])
        #self._log.debug('encode raw str:%s\n' %(encoded_str), extra={'namespace' : 'xmpp'})
        #str to dict  
        encoded_dict = eval(msg_context)
        for (k,v) in encoded_dict.items(): 
            self._log.debug('key is :%s'%k, extra={'namespace' : 'xmpp'})
            self._log.debug('val is :%s'%v, extra={'namespace' : 'xmpp'})
            if k == 'result':
                msg_ret['result'] = "is_reply"
                return 
            if k == 'cipher':
                cipher_get = v 
            if k == 'sign':
                sign_get = v 
        #decrypt
        if cipher_get != '' and sign_get != '':
            cipher_real = binascii.a2b_hex(cipher_get)
            self._log.debug('cipher_real:%s'%cipher_real, extra={'namespace' : 'xmpp'})
            sign_real = binascii.a2b_hex(sign_get)
            self._log.debug('sign_real:%s'%sign_real, extra={'namespace' : 'xmpp'})
            (result, PlainText) = m2c.utils_decrypt_verify(cipher_real, sign_real)
            self._log.debug('plainText:%s'%PlainText, extra={'namespace' : 'xmpp'})
            if result == True:
                msg_decode = PlainText 
                self._log.debug('Receive msg_decode:%s' %msg_decode, extra={'namespace' : 'xmpp'})
            else:
                self._log.debug('verify error!', extra={'namespace' : 'xmpp'})
                return 
        else:
            self._log.debug('trans crypt msg error!', extra={'namespace' : 'xmpp'})
            return 



        #self._log.debug('Receive msg_decode:%s' %msg_decode, extra={'namespace' : 'xmpp'})
        """
        encoded_str= binascii.a2b_hex(msg['body'])
        self._log.debug('encode raw str:%s\n' %(encoded_str), extra={'namespace' : 'xmpp'})
        #msg_b = bytes(s, encoding = "utf8")
        decoded_str = self.decode_crypt(encoded_str)
        self._log.debug('decoded_str:%s\n' %(decoded_str), extra={'namespace' : 'xmpp'})
        return 
        """
        try:
            eval(msg_decode)
        except Exception,e :
            self._log.debug('is not json!!', extra={'namespace' : 'xmpp'})
            msg_ret['result'] = "msg is not json format!"
            self.reply_msg(msg,msg_ret) 
            return 
        try:
            data = json.loads(msg_decode)
        except TypeError, err:
            self._log.debug('error:%s' %err, extra={'namespace' : 'xmpp'})
            msg_ret['result'] = "msg load error!"
            self.reply_msg(msg,msg_ret) 
            return 
        #finally:
        #    self._log.debug('finnally!', extra={'namespace' : 'xmpp'})
        #    return
            
        for (k,v) in data.items(): 
            self._log.debug('val is :%s'%k, extra={'namespace' : 'xmpp'})
            if k == 'result':
                msg_ret['result'] = "is_reply"
                return 

        result = callback_handle(data)
                  #result_encoded = encode_crypt(result)
                   #data['result'] = binascii.b2a_hex(result_encoded[0])

                   #data = binascii.b2a_hex(str_encoded)
                   #data[u'result'] = result.decode('utf-8')
        data['result'] = result
        encodedjson = json.dumps(data)
                   #msg_ret = encodedjson.encode('utf-8')
        msg_ret = encodedjson
        self.reply_msg(msg,msg_ret) 
        return 

    def reply_msg(self,msg_src,msg_reply):
        msg_src.reply("\n%s" % msg_reply).send()
        return

    def login(self):
        """
        Login to jabber server
        """
        if self.connect((self._server,self._server_port),reattempt = False):
            self._log.info('Connected !...', extra={'namespace' : 'xmpp'})
            self.process()
            self.loggedin = True
            return True
        else:
            self.loggedin = False 
            self._log.info('Connect failed!...', extra={'namespace' : 'xmpp'})
            return False 

    def subscribe(self, pres):
        """
        handle the friend's addaaaaaaing and subscription request
        1.filtering friends according to the [friend_pattern],in cement config file
        2.[friend_default_group],in cement config file
        """
        domain = self._friend_pattern
        if domain == None:
            self._log.info('domain: is not configured', extra={'namespace' : 'xmpp'})
        else:
            self._log.info('domain:%s' %domain, extra={'namespace' : 'xmpp'})
        
        group = self._friend_default_group
        if group == None:
            self._log.info('group: is not configured', extra={'namespace' : 'xmpp'})
        else:
            self._log.info('group:%s' %group, extra={'namespace' : 'xmpp'})

        jid_from = pres['from']
        if  jid_from.domain == domain:
            self.auto_authorize = True
            self.auto_subscribe = True
            self.send_presence(pto=pres['from'],
                           ptype='subscribed')
            self._log.info('jid:%s subscribed '%jid_from,extra={'namespace' : 'xmpp'})
            self.update_roster(pres['from'], name=jid_from.username, groups=[group])
        else :
            self.auto_authorize = False 
            self.auto_subscribe = False
            self.send_presence(pto=pres['from'],
                           ptype='unsubscribed')
            self._log.info('jid:%s unsubscribed '%jid_from,extra={'namespace' : 'xmpp'})

    def join_muc(self):
        self.plugin['xep_0045'].joinMUC(self.room,
                                        self.nick,
                                        # If a room password is needed, use:
                                        # password=the_room_password,
                                        wait=True)
        self._log.info('JoinMUC, room:%s' %self.room, extra={'namespace' : 'xmpp'})
        
