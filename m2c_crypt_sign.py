import os
import binascii
import M2Crypto
import time 
import datetime 

def utils_encrypt_sign(src_str):
    WriteRSA = M2Crypto.RSA.load_key('Bob-private.pem')
    CipherText = WriteRSA.private_encrypt(src_str,M2Crypto.RSA.pkcs1_padding)

    print "\nAlice's encrypted message to Bob:"
    print CipherText.encode('base64')
    MsgDigest = M2Crypto.EVP.MessageDigest('sha1')
    MsgDigest.update(CipherText)
    private_key = WriteRSA
    Signature = private_key.sign_rsassa_pss(MsgDigest.digest())
    #Signature = Alice.sign_rsassa_pss(MsgDigest.digest())
    # 2) Print the result
    print "Alice's signature for this message:"
    print Signature.encode('base64')
    return CipherText,Signature
 
 
def utils_decrypt_verify(cipher_str,sign):
   ReadRSA = M2Crypto.RSA.load_pub_key('Bob-public.pem')
   try:
       #PlainText = ReadRSA.private_decrypt(        cipher_str, M2Crypto.RSA.pkcs1_oaep_padding)
       PlainText = ReadRSA.public_decrypt(cipher_str, M2Crypto.RSA.pkcs1_padding)
   except:
       print "Error: wrong key?"
       PlainText = ""
    
   #if PlainText == "": //victor debug
   result = False 
   if PlainText != "":
       # Step 3, print the result of the decryption
       print "Message decrypted by Bob:"
       print PlainText
       # Step 4 (optional), verify the message was really sent by Alice
       # 1) Load Alice's public key
       #VerifyRSA = M2Crypto.RSA.load_pub_key('Alice-public.pem')
       VerifyRSA = ReadRSA 
       # 2 ) Verify the signature
       print "Signature verificaton:"
    
       MsgDigest = M2Crypto.EVP.MessageDigest('sha1')
       MsgDigest.update(cipher_str)
    
       if VerifyRSA.verify_rsassa_pss(MsgDigest.digest(), sign) == 1:
           print "This message was sent by Alice.\n"
           result = True
       else:
           print "This message was NOT sent by Alice!\n"
           result = False 
   return result,PlainText
"""
#if __name__="__main__":
# Seed the random number generator with 1024 random bytes (8192 bits)
#M2Crypto.Rand.rand_seed(os.urandom(1024))
# Generate public/private key pair for Alice
print "Generating a 1024 bit private/public key pair for Alice..."
Alice = M2Crypto.RSA.gen_key(4096, 65537)
 
Alice.save_key('Alice-private.pem', None)
 
# Save Alice's public key
Alice.save_pub_key('Alice-public.pem')
 
# Generate public/private key pair for Bob
print "Generating a 1024 bit private/public key pair for Bob..."
Bob = M2Crypto.RSA.gen_key(2048, 65537)
Bob.save_key('Bob-private.pem', None)
Bob.save_pub_key('Bob-public.pem')
"""
"""
str_send ="This is a secret message that can only be decrypted with Bob's private key"
#crypt sign
(cipher,sign) = utils_encrypt_sign(str_send)
print 'cipher:%s \n\n\n sign:%s \n'%(cipher,sign)

cipher_hex = binascii.b2a_hex(cipher)
sign_hex = binascii.b2a_hex(sign)
#msg_send = '{\"cipher\":\"%s\",\"sign\":\"%s\"}'%(cipher,sign)
msg_send = '{\'cipher\':\'%s\',\'sign\':\'%s\'}'%(cipher_hex,sign_hex)
print 'msg_send:%s \nend ...'%msg_send
#hex_msg= binascii.b2a_hex(msg_send)


#bin to ascii
#encoded_str= binascii.a2b_hex(msg['body'])
#encoded_str= binascii.a2b_hex(hex_msg)
#print encoded_str
#encoded_str = encoded_str +'\0'
get_dict = eval(msg_send)
print get_dict
a = "{'a': 'hi', 'b': 'there'}"
exec("c=" + a)
print c
#exec("get_dict=" + encoded_str)
for (k,v) in get_dict.items():
    if k == 'cipher':
        cipher_get = v
    if k == 'sign':
        sign_get = v


cipher_real = binascii.a2b_hex(cipher_get)
sign_real = binascii.a2b_hex(sign_get)
(result,Plain_Text) = utils_decrypt_verify(cipher_real, sign_real)
print Plain_Text
nowdate = datetime.datetime.now()
timestamp = nowdate.strftime("%Y%m%d%H%M%S")
print timestamp
#append the timestamp 
"""
