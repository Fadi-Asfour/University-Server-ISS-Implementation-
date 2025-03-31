# Project Overview

This project implements a secure client-server system designed to connect the University with its students and professors. The system is built using the Server-Client model over TCP/IP, relying on socket communication and multi-threading (or event-driven techniques) to support concurrent connections. Its primary goal is to enhance information security, ensuring confidentiality, integrity, non-repudiation, authentication, and authorization.

---

# System Architecture

## Client-Server Model
- The system operates with a server handling requests from multiple clients (students and professors) simultaneously via sockets using TCP/IP.

## Multi-Threading/Event-Driven
- The server is capable of handling multiple client connections concurrently, ensuring efficient communication.

---

# Security Features & Phases

## Phase One – Basic Connection & Authentication
- **Client Request:**  
  The client sends its login request with the server’s IP, port, username, and password.
- **Server Response:**  
  The server verifies the credentials and sends a success or failure message.

## Phase Two – Ensuring Confidentiality with Symmetric Encryption
- **Encryption of Sensitive Data:**  
  Critical information (e.g., national ID, mobile number, residence) is encrypted using a symmetric key that both the client and server have pre-agreed upon.

## Phase Three – Hybrid Encryption using PGP
- **Key Generation:**  
  Public-private key pairs are generated on the first connection and stored for each party.
- **Handshaking:**  
  During each connection, the server and client exchange public keys.
- **Session Key:**  
  The client generates a session key, encrypts it using PGP, and sends it to the server. All subsequent communication is secured using this session key.

## Phase Four – Digital Signature for Professors
- **Digital Signing:**  
  Professors digitally sign critical data (such as grade lists) to ensure data integrity and non-repudiation.
- **Verification:**  
  The signature assures that the data has not been altered in transit and that it indeed comes from the professor.

## Phase Five – Certificate-Based Authentication

### Signed Certificates
- **For Professors:**  
  - Professors generate a Certificate Signing Request (CSR) and submit it to a trusted Certificate Authority (CA) – in this case, the University’s president acts as the CA.
  - Upon successful verification, a digital certificate is issued and used for all future communications to prove the professor’s identity.

### Client Certificates
- Similarly, clients can be issued certificates to authenticate their identity and define their authorization levels.
