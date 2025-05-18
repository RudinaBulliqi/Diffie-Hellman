# Secure Chat Application

## Overview
This project implements a secure client-server chat application using Java with multiple cryptographic protocols to ensure confidentiality, integrity, and authentication. The system combines Diffie-Hellman key exchange for establishing a shared secret, AES for symmetric encryption of messages, and RSA signatures for message authentication.

## Features

- **End-to-End Encryption**: Uses AES-128 with keys derived from Diffie-Hellman key exchange
- **Perfect Forward Secrecy**: Each session generates new ephemeral DH keys
- **Message Authentication**: RSA signatures verify message integrity and sender authenticity
- **Mutual Authentication**: Server authenticates to client using RSA signatures
- **Secure Key Exchange**: 2048-bit Diffie-Hellman for key establishment
- **Secure Termination**: Clean session termination with "exit" command

## Cryptographic Components

1. **Key Exchange**: Diffie-Hellman (2048-bit)
2. **Symmetric Encryption**: AES-128 in ECB mode (Note: ECB has known weaknesses)
3. **Digital Signatures**: RSA (2048-bit) with SHA-256
4. **Key Derivation**: First 16 bytes of DH shared secret used as AES key

## Prerequisites

- Java Development Kit (JDK) 8 or later
- Basic understanding of cryptographic concepts

## How to Run

1. **Start the Server**:
   ```bash
   javac Server.java
   java Server
2. **Start the Client**:
   ```bash
   javac Client.java
   java Client
3. **Now you can text**
## Usage
1. The server will listen on port 5000

2. The client connects to localhost:5000

3. After successful connection and key exchange:

4. Server sends a welcome message with RSA signature

5. Client verifies the signature

6. Secure messaging begins

7. Type messages in the console and press Enter to send

8. Type "**exit**" to terminate the session cleanly.
   
