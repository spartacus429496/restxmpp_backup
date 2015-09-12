from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random

#generate Public/private key pair
random_generator = Random.new().read
private= RSA.generate(1024, random_generator)
print private 
#private = RSA.generate(1024)
public  = private.publickey()

#export and save
priv = private.exportKey()
pub = public.exportKey()
print priv
print pub
pubfile = open('pub_file_rsa.pem','w+')
pubfile.write(pub)
pubfile.close()

priv_file = open('priv_file_rsa.pem','w+')
priv_file.write(priv)
priv_file.close()


#encrypt
str = 'test rsa !!'
file_tmp = open('./pub_file_rsa.pem','r')
rsa_public_key = RSA.importKey(file_tmp.read())
en_s = rsa_public_key.encrypt(str,32) 
print en_s

#decrypt
file_tmp = open('./priv_file_rsa.pem','r')
rsa_private_key = RSA.importKey(file_tmp.read())
de_s = rsa_private_key.decrypt(en_s) 
print de_s

#sign
text = 'abcdefgh'
hash = SHA256.new(text).digest()
signature = rsa_private_key.sign(hash, '')

#verify
text_check = 'abcdefgh'
hash = SHA256.new(text_check).digest()
result = rsa_public_key.verify(hash, signature)
print result
