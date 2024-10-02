# Advanced-File-Encryption-System

# Project Overview

This project explores the implementation of various cryptographic algorithms, focusing on hybrid encryption systems and secure key exchanges. Through practical applications, we implemented both symmetric and asymmetric encryption, tested the performance of several algorithms, and incorporated secure key exchange protocols like Diffie-Hellman (DH). Additionally, the project supports stream encryption, making it possible to handle large files without loading them entirely into memory. This was achieved by leveraging the OpenSSL cryptographic library, which is widely used in securing communication channels and safeguarding sensitive data.

# Key Components & Features

- Symmetric Encryption (AES, Blowfish, ChaCha20)
  
  Symmetric encryption uses a single key for both encryption and decryption, making it extremely fast and efficient for encrypting large datasets.
  
  AES (Advanced Encryption Standard): AES is a widely adopted encryption standard, known for its robustness and speed. We implemented AES-256, which uses a 256-bit key for encryption. AES is particularly useful    for encrypting files and data streams in real-time.

  Blowfish: Blowfish is another fast block cipher encryption technique, offering a variable key length (32 to 448 bits) and ensuring fast encryption/decryption with smaller computational footprints. It's often     used in situations requiring high speed but lower security requirements compared to AES.

  ChaCha20: ChaCha20 is a stream cipher known for its high speed and security, often used as an alternative to AES in performance-critical applications. It’s efficient in both software and hardware and is p        popular in modern security protocols like TLS.

  Skills Gained:

  - Understanding of the differences between block ciphers (AES, Blowfish) and stream ciphers (ChaCha20).
  - Hands-on experience generating secure random keys and IVs (Initialization Vectors) for each cipher.
  - Implementation of data padding and block management for algorithms like AES and Blowfish.

- Asymmetric Encryption (RSA, ECC)
  
  Asymmetric encryption uses two keys – a public key for encryption and a private key for decryption. It's highly secure, but slower than symmetric encryption. It's often used to encrypt smaller pieces of data     like encryption keys themselves (in hybrid systems).

  RSA (Rivest–Shamir–Adleman): RSA is one of the first public-key cryptosystems and is used for secure data transmission. It allows for secure encryption of the symmetric AES key, making hybrid encryption          possible.
  ECC (Elliptic Curve Cryptography): ECC is a modern asymmetric encryption technique, offering similar security levels to RSA but with much smaller key sizes. This results in better performance, particularly in   devices with limited processing power.

  Skills Gained:

  - Proficiency in generating public/private key pairs and storing them securely in PEM format using OpenSSL.
  - Gained an understanding of how RSA encryption is used for securely exchanging keys in hybrid encryption systems.
  - Learned the advantages of ECC in modern cryptography, particularly its performance benefits and its applicability in secure communication protocols like TLS.

- Hybrid Encryption System (AES + RSA)

  Hybrid encryption combines the speed of symmetric encryption with the security of asymmetric encryption. The key idea is to encrypt the actual message with a fast symmetric algorithm (e.g., AES) and then         securely transmit the symmetric key using an asymmetric algorithm (e.g., RSA).

  Workflow:

  Generate a random AES key for symmetric encryption.
  
  Encrypt the message using AES.
  
  Encrypt the AES key using the RSA public key.
  
  Send the encrypted message and the encrypted AES key to the recipient.
  
  The recipient decrypts the AES key using their private RSA key and uses it to decrypt the message.

  Skills Gained:

  - Learned how to combine different cryptographic techniques into a cohesive system.
  - Understood the practical use cases for hybrid encryption, such as encrypted file storage and secure messaging.
  - Implemented error-handling mechanisms to ensure that any failure in the encryption or decryption process is properly reported.

- Diffie-Hellman Key Exchange Protocol
  The Diffie-Hellman (DH) key exchange protocol allows two parties to establish a shared secret over an unsecured communication channel without directly transmitting the key. This method ensures that even if an    attacker intercepts the communication, they cannot derive the shared key.

  Workflow:

  Each party generates a private key and calculates a corresponding public key.

  They exchange public keys.

  Each party uses their private key and the other party's public key to compute the shared secret.

  Both parties end up with the same shared secret without ever transmitting the secret itself.

  Skills Gained:

  - Understood the mathematical principles behind DH and its importance in secure communication.
  - Implemented DH in C++ using OpenSSL, ensuring secure key exchange for future communications.
  - Gained experience in preventing man-in-the-middle attacks by securing the key exchange process.

- Stream Encryption for Large Files
  One challenge of encrypting large files is memory management. By using stream encryption, files can be encrypted in chunks, avoiding the need to load the entire file into memory at once.

  Features:

  Support for encrypting and decrypting large files (e.g., multi-gigabyte files) using a stream-based approach.
  
  Efficiently handles input/output operations by reading and writing data in manageable blocks, ensuring minimal memory usage.

  Skills Gained:

  - Implemented file encryption using stream ciphers like AES and ChaCha20 in real-time.
  - Learned how to manage file I/O efficiently and securely using OpenSSL.
  - Understood the practical challenges of working with large data and how to overcome them using streaming techniques.

- HMAC (Hash-based Message Authentication Code)
  HMAC ensures that the data being transmitted is authentic and has not been altered. It provides both data integrity and authenticity.

  Implementation:

  We calculate an HMAC for every message encrypted with a symmetric algorithm.

  The HMAC is transmitted along with the ciphertext.

  Upon decryption, the HMAC is recalculated and compared with the transmitted HMAC to ensure the integrity of the data.

  Skills Gained:

  - Understood the importance of message integrity in secure communications.
  - Gained experience in generating and verifying HMAC using OpenSSL functions.
  - Integrated HMAC verification with the encryption/decryption pipeline to ensure data authenticity.

# Performance Testing

  The project also included a performance analysis of different cryptographic algorithms. Testing was done on:

  AES, Blowfish, and ChaCha20 for symmetric encryption.
  
  RSA and ECC for asymmetric encryption.

  Skills Gained:

  - Designed and implemented a performance benchmarking system to compare encryption speeds and memory usage.
  - Learned how to optimize cryptographic systems based on their use case (e.g., AES for large file encryption, ChaCha20 for performance-critical operations).
  - Gained a deeper understanding of trade-offs between security, performance, and computational complexity in cryptography.
    
# Future Enhancements

- Improved Key Management: Integrate secure cloud-based key management (e.g., AWS KMS or Google Cloud KMS) for secure storage and retrieval of encryption keys.

- More Cryptographic Algorithms: Add support for modern algorithms such as X25519 for key exchanges and explore post-quantum cryptography algorithms like lattice-based encryption.

- Secure Authentication: Implement user authentication mechanisms to ensure that only authorized users can access the encryption system.

- Parallel Encryption: Implement multi-threaded encryption and decryption for large files to improve performance further by utilizing multiple CPU cores.

- Automated Testing Suite: Develop an automated testing framework for both unit and performance tests to ensure that all cryptographic operations are functioning as expected across various scenarios and data types.

# Conclusion

  This project provided a deep dive into cryptographic systems and their real-world applications. The combination of symmetric and asymmetric encryption, along with key exchange protocols like Diffie-Hellman,      allowed for a robust encryption system suitable for secure communication, file encryption, and data integrity checks. Through the use of OpenSSL, I gained valuable experience in working with cryptographic        libraries and implemented secure solutions for large-scale data encryption.

