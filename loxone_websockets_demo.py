#Loxone Websocket Demo (developed on Python 3.7.7, Thonny)
#This is a demo program to establish a websocket connection to the loxone miniserver
#Referencing https://www.loxone.com/dede/wp-content/uploads/sites/2/2020/05/1100_Communicating-with-the-Miniserver.pdf
#This is a quite crappy documentation
#Here's the summary for a Miniserver Ver.1
#Due to security requirements, the communication between Miniserver and client needs to be encrypted
#In order to allow random clients to connect, a fixed shared secret cannot be used. However, as en encryption
#mechanism AES was chosen, which is a symmetric cryptographic method meaning the keys are the same on receiving
#and sending end. To overcome this, the client will define which AES key/iv to use and let the Miniserver know.
#To do so, the Miniserver provides its public RSA key to allow an assymetric encryption to be used for sending
#the AES key/iv pair. RSA limits the size of the payload - that's why it is not an option to only use RSA
#Furthermore, to authenticate, nowadays a token is used instead of user/password for each request.
#So, generally you could say we are:
# 1) Defining the AES Key and IV on the client side (in this program)
# 2) Retrieving the RSA public key and encrypting the AES Key with it
# 3) Send the AES Key/IV to the Miniserver in a key exchange
# 4) Request an authentication token (as we assume that we don't have one yet)
# 4a) Hash the User and Password to pass to the Miniserver to get the token
# 4b) Encrypt the Command using the AES Key and IV
# 5) wait for something to happen (maybe you now press some key in your home...)

#Imports
import requests   #lib for GET, POST, PUT etc.
import websockets #lib for websockets
import asyncio    #Asynchronous operation is necessary to deal with websockets

#Install pyCryptoDome NOT pyCrypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5

import base64    #necessary to encode in Base64
import secrets   #helpful to produce hashes and random bytes
import binascii  #hexlify/unhexlify allows to get HEX-Strings out of bytes-variables
import json      #working with JSON
import hashlib   #Hashing
import hmac      #Key-Hashing
import urllib    #necessary to encode URI-compliant
import os        #to access environment variables in .env

#Some Configuration/Definition --> Edit as needed

#Fixed values (for demo purpose only) - should be replaced by randomly generated (page 7, step 4 & 5)
aes_key = str("6A586E3272357538782F413F4428472B4B6250655368566B5970337336763979")
aes_iv = str("782F413F442A472D4B6150645367566B")

# Configuration

#Either you have a .env-File with the following settings OR Fill your own values here in the script
#LOX_USER = "user1"
#LOX_PASSWORD = "passwordxyz"
#LOX_IP = "192.168.1.1"
#LOX_PORT = "80"
try:
    myUser = os.environ["LOX_USER"]
except:
    myUser = "user1"
    
try:
    myPassword = os.environ["LOX_PASSWORD"]
except:
    myPassword = "passwordxyz"
    
try:
    myIP = os.environ["LOX_IP"]
except:
    myIP = "192.168.1.1"

try:
    myPort = os.environ["LOX_PORT"]
except:
    myPort = "80"

myUUID = "093302e1-02b4-603c-ffa4ege000d80cfd" #A UUID of your choosing --> you can use the one supplied as well
myIdentifier = "lox_test_script" #an identifier of your chosing
myPermission = 2 #2 for short period, 4 for long period

rsa_pub_key = None #possibility to set the key for debugging, e.g. "-----BEGIN PUBLIC KEY-----\nMxxxvddfDCBiQKBgQCvuJAG7r0FdysdfsdfBl/dDbxyu1h0KQdsf7cmm7mhnNPCevRVjRB+nlK5lljt1yMqJtoQszZqCuqP8ZKKOL1gsp7F0E+xgZjOpsNRcLxglGImS6ii0oTiyDgAlS78+mZrYwvow3d05eQlhz6PzqhAh9ZHQIDAQAB\n-----END PUBLIC KEY-----"


### These are the functions used ###
### sync functions ###
# Get the RSA public key from the miniserver and format it so that it is compliant with a .PEM file 
def prepareRsaKey():
    response = requests.get("http://{}:{}/jdev/sys/getPublicKey".format(myIP, myPort))
    rsa_key_malformed = response.json()["LL"]["value"]
    rsa_key_malformed = rsa_key_malformed.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n")
    rsa_key_wellformed = rsa_key_malformed.replace("-----END CERTIFICATE-----", "\n-----END PUBLIC KEY-----")
    print("RSA Public Key: ", rsa_key_wellformed)
    return rsa_key_wellformed


#Async Functions

#Websocket connection to Loxone
async def webSocketLx():
    
    #Encrypt the AES Key and IV with RSA (page 7, step 6)
    sessionkey = await create_sessionkey(aes_key, aes_iv)
    print("Session key: ", sessionkey) 
    
    #start websocket connection (page 7, step 3 - protocol does not need to be specified apparently)
    async with websockets.connect("ws://{}:{}/ws/rfc6455".format(myIP, myPort)) as myWs:
        
        #Send Session Key (page 8, step 7)
        await myWs.send("jdev/sys/keyexchange/{}".format(sessionkey))
        await myWs.recv()
        response = await myWs.recv()
        sessionkey_answer = json.loads(response)["LL"]["value"]
        
        #Now a ramdom salt of 2 bytes is added (page 8, step 8)
        aes_salt = binascii.hexlify(secrets.token_bytes(2)).decode()
        
        #Now prepare the token collection command with command encryption
        #Objective is to: Request a JSON Web Token “jdev/sys/getjwt/{hash}/{user}/{permission}/{uuid}/{info}”
        #--> This request must be encrypted
        # page 8, step 9b
        
        #Sending encrypted commands over the websocket (page 27, step 1)
        # Get the JSON web token (page 22, 23)
        getTokenCommand = "salt/{}/jdev/sys/getjwt/{}/{}/{}/{}/{}".format(aes_salt, await hashUserPw(myUser, myPassword), myUser, myPermission, myUUID, myIdentifier)
        print(getTokenCommand)
        
        #Now encrypt the command with AES (page 21 step 1 & 2)
        encrypted_command = await aes_enc(getTokenCommand, aes_key, aes_iv)
        message_to_ws = "jdev/sys/enc/{}".format(encrypted_command) # page 21, step 3
        print("Message to be sent: ", message_to_ws)
        
        #Send message to get a JSON webtoken
        await myWs.send(message_to_ws)
        await myWs.recv()
        print(await myWs.recv()) #And if you get back a 200 the connection is established
        
        
# Function to RSA encrypt the AES key and iv
async def create_sessionkey(aes_key, aes_iv):
    payload = aes_key + ":" + aes_iv
    payload_bytes = payload.encode()
    #RSA Encrypt the String containing the AES Key and IV
    #https://8gwifi.org/rsafunctions.jsp
    #RSA/ECB/PKCS1Padding
    pub_key = RSA.importKey(rsa_pub_key)
    encryptor = PKCS1_v1_5.new(pub_key)
    sessionkey = encryptor.encrypt(payload_bytes)
    #https://www.base64encode.org/ to compare
    return base64.standard_b64encode(sessionkey).decode()
    
    
# AES encrypt with the shared AES Key and IV    
async def aes_enc(text, aes_key, aes_iv):
    key = binascii.unhexlify(aes_key)
    iv = binascii.unhexlify(aes_iv)
    print("Key: ", key, "IV: ", iv)
    encoder = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_msg = encoder.encrypt(await pad(text.encode()))
    b64encoded = base64.standard_b64encode(encrypted_msg)
    return urllib.parse.quote(b64encoded, safe="") #Return url-Encrypted
 

# ZeroBytePadding to AES block size (16 byte) to allow encryption 
async def pad(byte_msg):
    return byte_msg + b"\0" * (AES.block_size - len(byte_msg) % AES.block_size) #ZeroBytePadding / Zero Padding


# Key-Hash the User and Password HMAC-SHA1 (page 22)
async def hashUserPw(user, password):
    # Get the key to be used for the HMAC-Hashing and the Salt to be used for the SHA1 hashing
    response = requests.get("http://{}:{}/jdev/sys/getkey2/{}".format(myIP, myPort, user))
    print(response.text)
    userKey = response.json()["LL"]["value"]["key"]
    userSalt = response.json()["LL"]["value"]["salt"]
    pwHash = await hash_Password(password, userSalt)
    print("PW Hash: ", pwHash)
    userHash = await digest_hmac_sha1("{}:{}".format(user, pwHash), userKey)
    #The userHash shall be left like it is
    return userHash
    

# Hash the Password plain and simple: SHA1 (page 22)
async def hash_Password(password, userSalt):
    #check if result is this: https://passwordsgenerator.net/sha1-hash-generator/
    tobehashed = password + ":" + userSalt
    print("To be hashed: ", tobehashed)
    hash = hashlib.sha1(tobehashed.encode())
    #according to the Loxone Doc, the password Hash shall be upper case
    hashstring = hash.hexdigest()
    print("Hashed: ", hashstring.upper())
    return hashstring.upper()
    

# HMAC-SHA1 hash something with a given key
async def digest_hmac_sha1(message, key):
    #https://gist.github.com/heskyji/5167567b64cb92a910a3
    #compare: https://www.liavaag.org/English/SHA-Generator/HMAC/  -- key type: text, output: hex
    print("hmac sha1 input: ", message)
    hex_key = binascii.unhexlify(key)
    print("Hex Key: ", hex_key)
    message = bytes(message, 'UTF-8')
    
    digester = hmac.new(hex_key, message, hashlib.sha1)
    signature1 = digester.digest()
    
    signature2 = binascii.hexlify(signature1)    
    print("hmac-sha1 output: ", signature2.decode())
    #return a hex string
    return signature2.decode()
    
    
### THIS is the actual program that executes - type: python loxone_websockets_demo.py ###
rsa_pub_key = prepareRsaKey() #Retrieve the public RSA key of the miniserver (page 7, step 2)
asyncio.get_event_loop().run_until_complete(webSocketLx()) #Start the eventloop (async) with the function webSocketLx


    

