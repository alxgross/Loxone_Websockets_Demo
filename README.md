# Loxone_Websockets_Demo
 Python Script showcasing a websocket connection to a Loxone Miniserver v.11.1

Developed with Thonny (running python 3.7.7) - a simple but helpful python IDE (https://thonny.org/)

This is a demo program to establish a websocket connection to the loxone miniserver
Referencing https://www.loxone.com/dede/wp-content/uploads/sites/2/2020/05/1100_Communicating-with-the-Miniserver.pdf

## Summary
Connecting to a Miniserver Ver.1
Due to security requirements, the communication between Miniserver and client needs to be encrypted.
In order to allow random clients to connect, a fixed shared secret cannot be used. However, as en encryption
mechanism AES was chosen, which is a symmetric cryptographic method meaning the keys are the same on receiving
and sending end. To overcome this, the client will define which AES key/iv to use and let the Miniserver know.

To do so, the Miniserver provides its public RSA key to allow an assymetric encryption to be used for sending
the AES key/iv pair. RSA limits the size of the payload - that's why it is not an option to only use RSA
Furthermore, to authenticate, nowadays a token is used instead of user/password for each request.

So, generally you could say we are:
1) Defining the AES Key and IV on the client side (in this program)
2) Retrieving the RSA public key and encrypting the AES Key with it
3) Send the AES Key/IV to the Miniserver in a key exchange
4) Request an authentication token (as we assume that we don't have one yet)
    1) Hash the User and Password to pass to the Miniserver to get the token
    2) Encrypt the Command using the AES Key and IV
5) wait for something to happen (maybe you now press some key in your home...)
