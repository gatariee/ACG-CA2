Suggestions:
============================================================================================

1.  The RSA encryption key should be stored in a secure location, such as a keystore, and should be protected with a passphrase.

2.  The RSA encryption should be used to encrypt the AES key before sending it to the server, so that the key is protected during transmission.

3.  The AES encryption key should be generated dynamically for each session, and should be discarded when the session is over.

4.  The data integrity should be verified on both client and server side, for example by adding a HMAC for example.

5.  The script could also include a mechanism for handling the case where the server's public key is not authentic (e.g. a man-in-the-middle attack)

6.  You could consider to add a way to handle errors, for example if the connection is lost.

7.  The script should also take care of handling the case where the server is down, or the connection is lost.