# -*- encoding: UTF-8 -*- 
import base64
from M2Crypto import * 
#发送方对数据进行签名 
m=EVP.MessageDigest("sha1") #先计算散列值 
m.update("fish is here") 
digest=m.final() 
key_str=file("./priv_file_rsa.pem","rb").read() #读入私钥 
key=RSA.load_key_string(key_str, util.no_passphrase_callback) 
result=key.sign(digest, "sha1") #签名后得到的数据。与原始数据一起发送出去。 
  
signature = base64.b64encode(result)


#接收方验证数据 
m=EVP.MessageDigest("sha1") #先计算散列值 
m.update("fish is here 33") 
digest=m.final() #先计算散列值 
cert_str=file("./pub_file_rsa.pem", "rb").read() #读入公钥 
mb=BIO.MemoryBuffer(cert_str) 
cert=RSA.load_pub_key_bio(mb) #RSA模式没有load_pub_key_string()方法，需自行使用MemoryBuffer 
#end = cert.verify(digest, result, "sha1") 
#print end

binary_signature = base64.b64decode(signature)
assert cert.verify(digest, binary_signature , "sha1"), 'Certificate Verification Failed'
"""
from M2Crypto import RSA, EVP
import base64, hashlib

text = "some text"

pkey = EVP.load_key("./priv_file_rsa.pem")  #"mykey.pem" was generated as: openssl genrsa -des3 -out mykey.pem 2048
pkey.sign_init()
pkey.sign_update(text)
signature = pkey.sign_final()
print base64.b64encode(signature)
"""

