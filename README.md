# File-encryption
A File Encryption Application using AES-256 encryption and user passphrase protection

# File Encryption Application

This repository contains an authorization application for encrypting files and directories using AES-256 encryption. The application securely protects encryption keys with a user-provided passphrase, ensuring that neither the passphrase nor the encryption keys are stored in plaintext.

## Features

- *File/Directory Encryption:* Encrypt files or directories using AES-256 encryption with a randomly generated File Encryption Key (FEK).
- *Key Protection:* Protect the FEK with a user-provided passphrase.
- *Secure Storage:* Ensure that both the passphrase and the FEK are not stored in plaintext.
- *User Authentication:* Retrieve and decrypt the encrypted files or directories upon successful user authentication.

## Prerequisites

- *Linux File System Operations*
- *Cryptographic Algorithms*
- *Programming Skills:* Proficiency in system-level programming with languages like C, C++, or Python.

## Infrastructure Requirements

- *Hardware:* Any x86-based Desktop or Server running Linux.

## Installation

1. *Clone the Repository:*
    sh
    git clone https://github.com/your-username/file-encryption-app.git
    cd file-encryption-app
    

2. *Dependencies:*
   Ensure you have the necessary dependencies installed. For Python, you can install the required packages using:
    sh
    pip install -r requirements.txt
    

3. *Run the Application:*
    sh
    python app.py
    

## Usage

### Encrypting a File or Directory

1. *Run the Application:*
    sh
    python app.py
    
2. *Select "Encrypt" Operation.*
3. *Browse and Select the File or Directory.*
4. *Enter the Passphrase.*
5. *Click "Encrypt" Button.*

### Decrypting a File or Directory

1. *Run the Application:*
    sh
    python app.py
    
2. *Select "Decrypt" Operation.*
3. *Browse and Select the Encrypted File or Directory.*
4. *Enter the Passphrase.*
5. *Click "Decrypt" Button.*

## Implementation Details

### Encryption Process

1. Generate a random File Encryption Key (FEK).
2. Encrypt the specified file or directory using the FEK.
3. Derive a key from the user passphrase using a Key Derivation Function (KDF).
4. Encrypt the FEK with the derived key and store it in a secure file.

### Decryption Process

1. Authenticate the user passphrase by deriving the key using the same KDF.
2. Decrypt the stored FEK using the derived key.
3. Use the decrypted FEK to decrypt the specified file or directory.

### Key Derivation Function (KDF)

The application uses a standard Key Derivation Function (KDF) to generate deterministic keys from the user passphrase. This ensures that the same passphrase will always generate the same key, which is crucial for decrypting the FEK.

## Security Considerations

- *Passphrase Protection:* The user passphrase is never stored in plaintext. It is only used to derive a key for encrypting and decrypting the FEK.
- *FEK Security:* The File Encryption Key (FEK) is encrypted with a key derived from the user passphrase and is never stored in plaintext.
- *Strong Encryption:* The application uses AES-256, a strong and widely accepted encryption algorithm.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [OpenSSL](https://www.openssl.org/) for cryptographic functions.
- [PyCryptodome](https://www.pycryptodome.org/) for Python cryptographic functions.
- [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) for the Key Derivation Function.

## Contact

For any questions or suggestions, please contact [your-email@example.com](mailto:your-email@example.com).
