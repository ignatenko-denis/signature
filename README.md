# Digital signature

A [Digital signature](https://en.wikipedia.org/wiki/Digital_signature) is a mathematical scheme 
for verifying the authenticity of digital messages or documents. 
A valid digital signature, where the prerequisites are satisfied, 
gives a recipient very high confidence that the message was 
created by a known sender (authenticity), and that the message was not altered in transit (integrity).

Digital signatures employ asymmetric cryptography. 
In many instances, they provide a layer of validation and security to messages sent 
through a non-secure channel: Properly implemented, 
a digital signature gives the receiver reason to believe the message was sent 
by the claimed sender. Digital signatures are equivalent to traditional handwritten signatures 
in many respects, but properly implemented digital signatures are more difficult 
to forge than the handwritten type. Digital signature schemes, 
in the sense used here, are cryptographically based, and must be implemented properly to be effective. 
They can also provide non-repudiation, meaning that the signer cannot successfully claim they did not sign a message, 
while also claiming their private key remains secret. 
Further, some non-repudiation schemes offer a timestamp for the digital signature, 
so that even if the private key is exposed, the signature is valid. 
Digitally signed messages may be anything representable as a bitstring: 
examples include electronic mail, contracts, or a message sent via some other cryptographic protocol.


A digital signature scheme typically consists of three algorithms:
- A key generation algorithm that selects a private key uniformly at random from a set of possible private keys. 
The algorithm outputs the private key and a corresponding public key.
- A signing algorithm that, given a message and a private key, produces a signature.
- A signature verifying algorithm that, given the message, public key and signature, 
either accepts or rejects the message's claim to authenticity.

Two main properties are required. 
- First, the authenticity of a signature generated from a fixed message and 
fixed private key can be verified by using the corresponding public key. 
- Secondly, it should be computationally infeasible to generate a valid signature 
for a party without knowing that party's private key. 

A digital signature is an authentication mechanism that enables the creator of the message to attach a code that acts as a signature.

### How add digital signature to file and validate it in terminal?
#### Before you start
1. install the latest JDK with `keytool`.
2. install `openssl`
```shell
brew install openssl
```
#### Steps
First we need to create a private, public key pair for asymmetric encryption.
We can generate a keystore using keytool with a private key.
```shell
keytool -genkey -alias testaes -storetype JKS -keystore keystore.jks -keyalg RSA -keysize 2048
```
For asymmetric encryption and decryption we need to extract the private key and the public key from this keystore.
```shell
keytool -importkeystore -srckeystore keystore.jks -srcalias testaes -destalias testaes -destkeystore keystore.p12 -deststoretype PKCS12
```
This command will convert our JKS keystore to a PKCS12 Keystore.
```shell
openssl pkcs12 -in keystore.p12 -nodes -nocerts -out private_key.pem
```
This will save our private key as a private_key.pem file.
Then we can export the certificate for the private key from the keystore.
```shell
keytool -export -alias testaes -keystore keystore.jks -file cert.pem
```
This certificate contains the public key for the generated private key. 
We can export the public key from the certificate using openssl.
```shell
openssl x509 -inform der -pubkey -noout -in cert.pem  > public_key.pem
```
Now we have public key (public_key.pem) and private key (private_key.pem) for our asymmetric encryption.
Signing a file using private key
```shell
openssl dgst -sha256 -sign private_key.pem -out README.md.sign.sha256 README.md
```
This will output binary file of the signature. We can encode this binary file in base64 for our purposes.
```shell
openssl base64 -in README.md.sign.sha256 -out signature
```
Before validating the signature, we need to extract the binary file from the base64 encoded signature.
```shell
openssl base64 -d -in signature -out received.sign.sha256
```
This will output the binary file of the signature, 
and we can verify the signature with the file using the following command.
```shell
openssl dgst -sha256 -verify public_key.pem -signature received.sign.sha256 README.md

diff received.sign.sha256 README.md.sign.sha256
```
