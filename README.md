# Security Toolkit

## Video Demo: https://youtu.be/ZjyTdrHnEy0?si=0sn_zqxXsH5WpCO7

## Overview
The **Security Toolkit** is an all-in-one tool designed to provide a comprehensive suite of security-related utilities. This project offers functionalities such as encryption and decryption, file compression and decompression, password strength evaluation, system security checks, and more. The toolkit is built with a focus on cybersecurity enthusiasts, developers, and anyone interested in protecting their data and systems.

---

## Features

### 1. **Ping a Host**
- Test network connectivity by pinging a specific host.

### 2. **Base64 Encoding and Decoding**
- Encode and decode text using the Base64 standard.

### 3. **AES File Encryption and Decryption**
- Securely encrypt files using AES-256 encryption.
- Decrypt encrypted files with the correct password.

### 4. **Password Strength Checker**
- Evaluate the strength of a given password and provide feedback on its robustness.

### 5. **File Compression and Decompression**
- Compress files into `.zip` format.
- Decompress `.zip` files into specified directories.

### 6. **SQL Injection Tester**
- Analyze input strings to identify potential SQL injection vulnerabilities.

### 7. **VirusTotal File Upload**
- Upload files to VirusTotal for comprehensive malware scanning.

### 8. **System Security Check**
- Perform basic security checks on the system to identify potential vulnerabilities.

### 9. **File Analysis**
- Analyze a file's content and attributes for basic forensic insights.

---

## Installation

### Prerequisites
Ensure you have the following installed:
- GCC or any compatible C compiler
- OpenSSL library
- LibZip library

### Build Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Security-Toolkit.git
   cd Security-Toolkit
   ```

2. Compile the source code:
   ```bash
   sudo apt install libssl-dev
    ```
   ```bash
   sudo apt install libzip-dev
    ```
   ```bash
   sudo apt install libcurl4-openssl-dev
    ```
   ```bash
   gcc -Wall -Wextra -o security_toolkit main.c -lssl -lcrypto -lz -lzip -lcurl -lmagic
   ```

4. Run the toolkit:
   ```bash
   ./security_toolkit
   ```

---

## Usage

### Main Menu
Run the program to access an interactive menu. Choose the desired feature by entering the corresponding number:

1. **Ping a Host**: Enter a hostname or IP to test connectivity.
2. **Base64 Encode/Decode**: Input text to encode or decode.
3. **AES File Encryption/Decryption**:
   - Provide the input file path and a secure password.
   - Encrypted files will have a `.enc` extension.
   - Decrypted files will have a `.dec` extension.
4. **Password Strength Check**: Input a password and receive a strength score (0-8).
5. **SQL Injection Test**: Analyze user input for common SQL injection patterns.
6. **File Compression/Decompression**:
   - Compress files to `.zip` format.
   - Decompress files from `.zip` format to a directory.
7. **Upload to VirusTotal**: Enter a file path to upload it for malware analysis.
8. **System Security Check**: Run a scan for basic system vulnerabilities.
9. **File Analysis**: Analyze specific files for forensic details.

---

## Example

### Encrypting a File
1. Select the encryption option from the menu.
2. Provide the file path and a strong password.
3. The toolkit creates an encrypted file with the `.enc` extension.

### Decrypting a File
1. Select the decryption option from the menu.
2. Provide the `.enc` file path and the correct password.
3. The toolkit generates a decrypted file with the `.dec` extension.

---

## Contributing

We welcome contributions! If you'd like to enhance this toolkit:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your message here"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-branch-name
   ```
5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

## Acknowledgments

- **OpenSSL**: For encryption and decryption capabilities.
- **LibZip**: For file compression and decompression.
- **VirusTotal**: For malware scanning and analysis.

---

## Disclaimer

This toolkit is for educational and personal use only. The authors are not responsible for any misuse of the tool.

