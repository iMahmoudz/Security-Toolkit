#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <magic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <zlib.h>
#include <zip.h>
#include <curl/curl.h>
#include <unistd.h>

#define PING_PKT_SIZE 64
#define PORT_NUMBER 0
#define PING_SLEEP_RATE 1000000
#define RECV_TIMEOUT 1
#define MAX_PASSWORD_LEN 256
#define BUFFER_SIZE 4096
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32  // 256-bit key
#define AES_IV_SIZE 16   // 128-bit IV
#define API_URL "https://www.virustotal.com/api/v3/files"
#define API_KEY "eb94ffe75b9d6da9b9b47e376365c610827247223891e84d723061135c80d328"

// Function prototypes
void show_menu(void);
void ping_host();
char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int *outlen);
void aes_encrypt_file(const char *input_file, const char *key);
void aes_decrypt_file(const char *input_file, const char *key);
int check_password_strength(const char *password);
void analyze_file(const char *filename);
void system_security_check(void);
void compress_file(const char *input_file, const char *output_dir);
void decompress_file(const char *input_file, const char *output_dir);
void sql_injection_test(const char *input);

// Structure for ping packet
struct ping_pkt {
    struct icmphdr hdr;
    char msg[PING_PKT_SIZE - sizeof(struct icmphdr)];
};

// Function definitions

void show_menu(void) {
    printf("\n========== Security Toolkit v1.0 ==========\n");
    printf("1. Ping Host\n");
    printf("2. Base64 Encode\n");
    printf("3. Base64 Decode\n");
    printf("4. AES File Encryption\n");
    printf("5. AES File Decryption\n");
    printf("6. Password Strength Check\n");
    printf("7. Fille Malware Check\n");
    printf("8. File Analysis\n");
    printf("9. System Security Check\n");
    printf("10. File Compression\n");
    printf("11. File Decompression\n");
    printf("12. SQL Injection Test\n");
    printf("0. Exit\n");
    printf("===========================================\n");
    printf("Enter your choice: ");
}

void ping_host() {
    char host[256];
    printf("Enter the host to ping: ");
    scanf("%s", host);

    char command[300];
    snprintf(command, sizeof(command), "ping -c 4 %s", host);
    int ret = system(command);

    if (ret != 0) {
        printf("Error: Unable to ping the host %s.\n", host);
    }
}

// Base64 encoding implementation
char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *buffer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    buffer = (char *)malloc(bufferPtr->length);
    memcpy(buffer, bufferPtr->data, bufferPtr->length - 1);
    buffer[bufferPtr->length - 1] = 0;

    BIO_free_all(bio);
    return buffer;
}

// Password strength checker implementation
int check_password_strength(const char *password) {
    int score = 0;
    int length = strlen(password);
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;
    
    // Check length
    if (length >= 8) score += 1;
    if (length >= 12) score += 1;
    if (length >= 16) score += 1;
    
    // Check character types
    for (int i = 0; i < length; i++) {
        if (islower(password[i])) has_lower = 1;
        else if (isupper(password[i])) has_upper = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else has_special = 1;
    }
    
    score += has_lower + has_upper + has_digit + has_special;
    
    return score;
}

// Callback function to capture the response
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strcat((char *)userp, (char *)contents);
    return realsize;
}

// Structure to store response
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback function to handle response
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Helper function to read file contents
static size_t read_file(const char *filename, char **buffer) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return 0;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    *buffer = malloc(file_size);
    if (!*buffer) {
        fclose(file);
        return 0;
    }

    // Read file contents
    size_t bytes_read = fread(*buffer, 1, file_size, file);
    fclose(file);
    
    return bytes_read;
}

void upload_file_to_virustotal(const char *input_file) {
    CURL *hnd;
    CURLcode ret;
    char *file_buffer = NULL;
    size_t file_size;
    struct MemoryStruct chunk = {0};

    // Initialize response chunk
    chunk.memory = malloc(1);
    chunk.size = 0;

    // Read the file contents
    file_size = read_file(input_file, &file_buffer);
    if (!file_size) {
        fprintf(stderr, "Failed to read file\n");
        free(chunk.memory);
        return;
    }

    // Initialize CURL
    hnd = curl_easy_init();
    if (!hnd) {
        fprintf(stderr, "Failed to initialize CURL\n");
        free(file_buffer);
        free(chunk.memory);
        return;
    }

    // Create mime structure
    curl_mime *mime = curl_mime_init(hnd);
    if (!mime) {
        fprintf(stderr, "Failed to initialize MIME structure\n");
        free(file_buffer);
        free(chunk.memory);
        curl_easy_cleanup(hnd);
        return;
    }

    // Create mime part
    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        fprintf(stderr, "Failed to create MIME part\n");
        curl_mime_free(mime);
        free(file_buffer);
        free(chunk.memory);
        curl_easy_cleanup(hnd);
        return;
    }

    // Set up the file part
    curl_mime_name(part, "file");
    curl_mime_filename(part, input_file);
    curl_mime_data(part, file_buffer, file_size);

    // Set the URL
    curl_easy_setopt(hnd, CURLOPT_URL, API_URL);

    // Prepare API key header
    char api_header[1024];
    snprintf(api_header, sizeof(api_header), "x-apikey: %s", API_KEY);

    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, api_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    // Set mime data
    curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime);

    // Set write callback
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&chunk);

    // Enable verbose output for debugging
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);

    // Perform the request
    ret = curl_easy_perform(hnd);

    if (ret != CURLE_OK) {
        fprintf(stderr, "Request failed: %s\n", curl_easy_strerror(ret));
    } else {
        printf("Response: %s\n", chunk.memory);
    }

    // Clean up
    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_easy_cleanup(hnd);
    free(file_buffer);
    free(chunk.memory);
}

// Structure to hold file metadata
typedef struct {
    unsigned char md5[EVP_MAX_MD_SIZE];
    unsigned char sha1[EVP_MAX_MD_SIZE];
    unsigned char sha256[EVP_MAX_MD_SIZE];
    unsigned int md5_len;
    unsigned int sha1_len;
    unsigned int sha256_len;
    char mime_type[256];
    char file_type[256];
    long size;
    time_t created;
    time_t modified;
    time_t accessed;
    mode_t permissions;
    unsigned char header[32];
    size_t header_size;
} FileMetadata;

// Structure for file signatures
typedef struct {
    unsigned char *signature;
    size_t sig_length;
    const char *description;
} FileSignature;

// Helper function to convert bytes to human readable format
void format_size(long bytes, char *buffer) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double size = bytes;
    
    while (size >= 1024 && i < 4) {
        size /= 1024;
        i++;
    }
    
    sprintf(buffer, "%.2f %s", size, units[i]);
}

// Calculate file hashes using OpenSSL EVP interface
void calculate_hashes(FILE *file, FileMetadata *metadata) {
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();
    
    unsigned char buffer[4096];
    size_t bytes;

    EVP_DigestInit_ex(md5_ctx, EVP_md5(), NULL);
    EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL);
    EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL);

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(md5_ctx, buffer, bytes);
        EVP_DigestUpdate(sha1_ctx, buffer, bytes);
        EVP_DigestUpdate(sha256_ctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(md5_ctx, metadata->md5, &metadata->md5_len);
    EVP_DigestFinal_ex(sha1_ctx, metadata->sha1, &metadata->sha1_len);
    EVP_DigestFinal_ex(sha256_ctx, metadata->sha256, &metadata->sha256_len);

    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(sha256_ctx);

    // Reset file position
    fseek(file, 0, SEEK_SET);
}

// Initialize file signatures
FileSignature* init_signatures(size_t *sig_count) {
    static unsigned char PE[] = {0x4D, 0x5A};
    static unsigned char ELF[] = {0x7F, 0x45, 0x4C, 0x46};
    static unsigned char ZIP[] = {0x50, 0x4B, 0x03, 0x04};
    static unsigned char PNG[] = {0x89, 0x50, 0x4E, 0x47};
    static unsigned char JPEG[] = {0xFF, 0xD8, 0xFF};
    static unsigned char PDF[] = {0x25, 0x50, 0x44, 0x46};
    static unsigned char RAR[] = {0x52, 0x61, 0x72, 0x21};
    static unsigned char RTF[] = {0x7B, 0x5C, 0x72, 0x74};
    static unsigned char SHELL[] = {0x23, 0x21};
    static unsigned char GZIP[] = {0x1F, 0x8B};
    static unsigned char BZIP2[] = {0x42, 0x5A, 0x68};

    static FileSignature signatures[] = {
        {PE, 2, "Windows Executable (PE)"},
        {ELF, 4, "Linux Executable (ELF)"},
        {ZIP, 4, "ZIP Archive"},
        {PNG, 4, "PNG Image"},
        {JPEG, 3, "JPEG Image"},
        {PDF, 4, "PDF Document"},
        {RAR, 4, "RAR Archive"},
        {RTF, 4, "RTF Document"},
        {SHELL, 2, "Shell Script"},
        {GZIP, 2, "GZIP Archive"},
        {BZIP2, 3, "BZIP2 Archive"}
    };

    *sig_count = sizeof(signatures) / sizeof(FileSignature);
    return signatures;
}

// Detect file type based on magic numbers
void detect_file_type(const unsigned char *header, size_t header_size, char *file_type) {
    size_t sig_count;
    FileSignature *signatures = init_signatures(&sig_count);
    
    strcpy(file_type, "Unknown");
    
    for (size_t i = 0; i < sig_count; i++) {
        if (header_size >= signatures[i].sig_length &&
            memcmp(header, signatures[i].signature, signatures[i].sig_length) == 0) {
            strcpy(file_type, signatures[i].description);
            return;
        }
    }
}

void analyze_file(const char *filename) {
    FileMetadata metadata = {0};
    char size_str[32];
    char time_str[64];
    struct stat st;
    magic_t magic;
    
    printf("\n=== File Analysis Report ===\n");
    printf("Filename: %s\n", filename);
    printf("Analysis Time: %s\n", ctime(&(time_t){time(NULL)}));
    printf("----------------------------------------\n");

    // Open file
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("ERROR: Unable to open file for analysis\n");
        return;
    }

    // Get file metadata
    if (stat(filename, &st) == 0) {
        metadata.size = st.st_size;
        metadata.created = st.st_ctime;
        metadata.modified = st.st_mtime;
        metadata.accessed = st.st_atime;
        metadata.permissions = st.st_mode;
    }

    // Read file header
    metadata.header_size = fread(metadata.header, 1, sizeof(metadata.header), file);

    // Calculate hashes
    calculate_hashes(file, &metadata);

    // Detect MIME type using libmagic
    magic = magic_open(MAGIC_MIME_TYPE);
    if (magic && magic_load(magic, NULL) == 0) {
        const char *mime = magic_file(magic, filename);
        if (mime) {
            strncpy(metadata.mime_type, mime, sizeof(metadata.mime_type) - 1);
        }
    }

    // Detect file type
    detect_file_type(metadata.header, metadata.header_size, metadata.file_type);

    // Print basic information
    format_size(metadata.size, size_str);
    printf("File Size: %s (%ld bytes)\n", size_str, metadata.size);
    printf("File Type: %s\n", metadata.file_type);
    printf("MIME Type: %s\n", metadata.mime_type);
    
    // Print timestamps
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&metadata.created));
    printf("Created: %s\n", time_str);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&metadata.modified));
    printf("Modified: %s\n", time_str);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&metadata.accessed));
    printf("Accessed: %s\n", time_str);

    // Print permissions
    printf("Permissions: %o\n", metadata.permissions & 0777);
    
    // Print cryptographic hashes
    printf("\nCryptographic Hashes:\n");
    printf("MD5: ");
    for (unsigned int i = 0; i < metadata.md5_len; i++)
        printf("%02x", metadata.md5[i]);
    printf("\nSHA1: ");
    for (unsigned int i = 0; i < metadata.sha1_len; i++)
        printf("%02x", metadata.sha1[i]);
    printf("\nSHA256: ");
    for (unsigned int i = 0; i < metadata.sha256_len; i++)
        printf("%02x", metadata.sha256[i]);
    
    // Print file header
    printf("\n\nFile Header (first 32 bytes):\n");
    for (size_t i = 0; i < metadata.header_size; i++) {
        printf("%02X ", metadata.header[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("\nASCII Representation:\n");
    for (size_t i = 0; i < metadata.header_size; i++) {
        printf("%c", (metadata.header[i] >= 32 && metadata.header[i] <= 126) ? metadata.header[i] : '.');
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Cleanup
    if (magic) magic_close(magic);
    fclose(file);
    
    printf("----------------------------------------\n");
    printf("Analysis Complete\n\n");
}

// System security check implementation
void system_security_check(void) {
    printf("System Security Check Results:\n\n");
    
    // Check file permissions of sensitive directories
    printf("Checking sensitive directory permissions...\n");
    struct stat st;
    if (stat("/etc", &st) == 0) {
        printf("/etc permissions: %o\n", st.st_mode & 0777);
    }
    
    // Check running services
    printf("\nChecking running services...\n");
    system("ps aux | grep -E 'sshd|httpd|nginx' 2>/dev/null");
    
    // Check open ports
    printf("\nChecking open ports...\n");
    system("netstat -tuln 2>/dev/null | grep LISTEN");
    
    // Check system updates
    printf("\nChecking for system updates...\n");
    system("which apt >/dev/null 2>&1 && apt list --upgradable 2>/dev/null");
}

// Previous function declarations remain the same...

// Base64 decoding implementation
unsigned char *base64_decode(const char *input, int *outlen) {
    BIO *bio, *b64;
    int decodeLen = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(decodeLen);
    
    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *outlen = BIO_read(bio, buffer, decodeLen);
    
    BIO_free_all(bio);
    return buffer;
}

// Function to derive key and IV from a password using PBKDF2
int derive_key_and_iv(const char *password, unsigned char *key, unsigned char *iv) {
    unsigned char salt[8] = "random_s";  // Replace with a secure random salt
    if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, sizeof(salt), 10000, AES_KEY_SIZE + AES_IV_SIZE, key)) {
        fprintf(stderr, "Error: Failed to derive key and IV.\n");
        return 0;
    }
    memcpy(iv, key + AES_KEY_SIZE, AES_IV_SIZE);  // Split key and IV
    return 1;
}

// AES encryption implementation for files
void aes_encrypt_file(const char *input_file, const char *password) {
    FILE *f_input = fopen(input_file, "rb");
    if (!f_input) {
        printf("Error opening input file\n");
        return;
    }

    char output_file[BUFFER_SIZE];
    snprintf(output_file, sizeof(output_file), "%s.enc", input_file);  // Create output file path with .enc extension
    FILE *f_output = fopen(output_file, "wb");
    if (!f_output) {
        printf("Error opening output file\n");
        fclose(f_input);
        return;
    }

    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    if (!derive_key_and_iv(password, key, iv)) {
        fclose(f_input);
        fclose(f_output);
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("Error initializing encryption\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    fwrite(iv, 1, AES_BLOCK_SIZE, f_output);  // Write IV to output file

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, f_input)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            printf("Error encrypting data\n");
            fclose(f_input);
            fclose(f_output);
            return;
        }
        fwrite(outbuf, 1, outlen, f_output);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        printf("Error finalizing encryption\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }
    fwrite(outbuf, 1, outlen, f_output);

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_input);
    fclose(f_output);
    printf("File encrypted successfully!");
}

// AES decryption implementation for files
void aes_decrypt_file(const char *input_file, const char *password) {
    FILE *f_input = fopen(input_file, "rb");
    if (!f_input) {
        printf("Error opening input file\n");
        return;
    }

    char output_file[BUFFER_SIZE];
    snprintf(output_file, sizeof(output_file), "%s.dec", input_file);  // Create output file path with .dec extension
    FILE *f_output = fopen(output_file, "wb");
    if (!f_output) {
        printf("Error opening output file\n");
        fclose(f_input);
        return;
    }

    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    if (fread(iv, 1, AES_BLOCK_SIZE, f_input) != AES_BLOCK_SIZE) {
        printf("Error reading IV\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }

    if (!derive_key_and_iv(password, key, iv)) {
        fclose(f_input);
        fclose(f_output);
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("Error initializing decryption\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, f_input)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            printf("Error decrypting data\n");
            fclose(f_input);
            fclose(f_output);
            return;
        }
        fwrite(outbuf, 1, outlen, f_output);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        printf("Error finalizing decryption\n");
        fclose(f_input);
        fclose(f_output);
        return;
    }
    fwrite(outbuf, 1, outlen, f_output);

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_input);
    fclose(f_output);
    printf("File decrypted successfully!");
}

// Function to compress file to zip
void compress_file(const char *input_file, const char *output_dir) {
    char zip_file[BUFFER_SIZE];
    snprintf(zip_file, sizeof(zip_file), "%s/%s.zip", output_dir, input_file);  // Create zip file path with .zip extension

    int err = 0;
    zip_t *archive = zip_open(zip_file, ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (archive == NULL) {
        printf("Error opening zip file\n");
        return;
    }

    FILE *f_input = fopen(input_file, "rb");
    if (!f_input) {
        printf("Error opening input file for compression\n");
        return;
    }

    zip_source_t *source = zip_source_file(archive, input_file, 0, 0);
    if (source == NULL) {
        printf("Error creating zip source\n");
        return;
    }

    if (zip_file_add(archive, input_file, source, ZIP_FL_OVERWRITE) < 0) {
        printf("Error adding file to zip archive\n");
        return;
    }

    if (zip_close(archive) < 0) {
        printf("Error closing zip archive\n");
        return;
    }

    fclose(f_input);
    printf("File compressed to zip successfully to %s\n", zip_file);
}

// Function to decompress zip file
void decompress_file(const char *input_file, const char *output_dir) {
    int err;
    zip_t *archive = zip_open(input_file, 0, &err);
    if (!archive) {
        fprintf(stderr, "Error: Unable to open zip file '%s'.\n", input_file);
        return;
    }

    struct zip_stat stat;
    zip_stat_init(&stat);

    // Extract each file in the archive
    for (int i = 0; i < zip_get_num_entries(archive, 0); i++) {
        if (zip_stat_index(archive, i, 0, &stat) != 0) {
            fprintf(stderr, "Error: Failed to get file stats.\n");
            continue;
        }

        char outpath[BUFFER_SIZE];
        snprintf(outpath, sizeof(outpath), "%s/%s", output_dir, stat.name);

        FILE *outfile = fopen(outpath, "wb");
        if (!outfile) {
            fprintf(stderr, "Error: Unable to create output file '%s'.\n", outpath);
            continue;
        }

        struct zip_file *zfile = zip_fopen_index(archive, i, 0);
        if (!zfile) {
            fprintf(stderr, "Error: Unable to open file in zip archive.\n");
            continue;
        }

        char buffer[BUFFER_SIZE];
        zip_int64_t bytes_read;
        while ((bytes_read = zip_fread(zfile, buffer, sizeof(buffer))) > 0) {
            fwrite(buffer, 1, bytes_read, outfile);
        }

        zip_fclose(zfile);
        fclose(outfile);
    }

    zip_close(archive);
    printf("File decompressed successfully!");
}

// SQL injection tester implementation
void sql_injection_test(const char *input) {
    printf("\n--- SQL Injection Test ---\n");
    
    // Common SQL injection patterns
    const char *patterns[] = {
        "'", "--", ";", "/", "/", "1=1", "1=0",
        "OR 1=1", "OR 'x'='x'", "'; DROP TABLE", 
        "UNION SELECT", "EXEC xp_", "INTO OUTFILE", 
        "LOAD DATA", "' OR '1'='1", "\" OR \"1\"=\"1", 
        "admin' --", "admin' #", "' OR 1=1 --",
        "WAITFOR DELAY", "CHAR(", "NCHAR(", "CONVERT(", 
        "CAST(", NULL
    };
    
    printf("Input: \"%s\"\n", input);
    printf("Analyzing for potential SQL injection vulnerabilities...\n\n");

    int found = 0;

    // Check for SQL injection patterns
    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(input, patterns[i]) != NULL) {
            printf("- Detected potentially dangerous pattern: \"%s\"\n", patterns[i]);
            found = 1;
        }
    }

    // Check if the input is numeric, which can indicate numeric injection attempts
    int numeric_input = 1;
    for (size_t i = 0; i < strlen(input); i++) {
        if (!isdigit(input[i])) {
            numeric_input = 0;
            break;
        }
    }
    if (numeric_input) {
        printf("- Input is purely numeric: Potential risk of numeric-based injection\n");
        found = 1;
    }

    // Detect potential UNION-based or evasion techniques
    if (strcasestr(input, "union") || strcasestr(input, "select")) {
        printf("- Detected potential UNION/SELECT-based injection attempt\n");
        found = 1;
    }

    // Detect attempts to bypass using comments
    if (strcasestr(input, "/") || strcasestr(input, "/")) {
        printf("- Detected potential comment-based evasion attempt\n");
        found = 1;
    }

    if (!found) {
        printf("No potential SQL injection patterns detected.\n");
    }

    // Recommendations for protection
    printf("\n--- Recommendations ---\n");
    printf("1. Use prepared statements or parameterized queries.\n");
    printf("2. Implement strict input validation (whitelisting preferred).\n");
    printf("3. Avoid dynamic SQL generation with user inputs.\n");
    printf("4. Sanitize all inputs and encode outputs where applicable.\n");
    printf("5. Use a web application firewall (WAF) for additional protection.\n");
    printf("-----------------------\n");
}

void wait_for_user(void) {
    int choice;
    while (1) {
    	usleep(500000);
        printf("\n-------------------------------------------\n");
        printf("To continue, press 1\n");
        printf("To exit the program, press 0\n");
        printf("-------------------------------------------\n");
        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Error: Invalid input. Please enter a valid option.\n");
            exit(EXIT_FAILURE);
        }
        if (choice == 1) {
            break;
        } else if (choice == 0) {
            printf("Thank you for using the Security Toolkit. Goodbye!\n");
            exit(EXIT_SUCCESS);
        } else {
            printf("Invalid choice. Please try again.\n");
        }
    }
}

int main(void) {
    int choice;
    char input[BUFFER_SIZE];
    //char output[BUFFER_SIZE];
    char input_file[BUFFER_SIZE];
    char output_dir[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    char filename[256];
    //char zip_file[BUFFER_SIZE];

    while (1) {
        show_menu();
        scanf("%d", &choice);
        getchar(); // Consume newline
        

        switch (choice) {
            case 1:
                ping_host();
                wait_for_user();
                break;
                
            case 2:
                printf("Enter text to encode: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = 0;
                char *encoded = base64_encode((unsigned char *)input, strlen(input));
                printf("Encoded: %s\n", encoded);
                free(encoded);
                wait_for_user();
                break;
                
            case 3:
                printf("Enter text to decode: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = 0;
                int outlen;
                unsigned char *decoded = base64_decode(input, &outlen);
                printf("Decoded: %.*s\n", outlen, decoded);
                free(decoded);
                wait_for_user();
                break;
                
            case 4:
                printf("Enter the input file path to encrypt: ");
                fgets(input_file, sizeof(input_file), stdin);
                strtok(input_file, "\n");  // Remove newline character
                printf("Enter the password for encryption: ");
                fgets(password, sizeof(password), stdin);
                strtok(password, "\n");  // Remove newline
                aes_encrypt_file(input_file, password);
                wait_for_user();
                break;
                
            case 5:
                printf("Enter the input file path to decrypt: ");
                fgets(input_file, sizeof(input_file), stdin);
                strtok(input_file, "\n");
                printf("Enter the password for decryption: ");
                fgets(password, sizeof(password), stdin);
                strtok(password, "\n");
                aes_decrypt_file(input_file, password);
                wait_for_user();
                break;
                
            case 6:
                printf("Enter password to check: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = 0;
                int strength = check_password_strength(input);
                printf("Password strength score (0-8): %d\n", strength);
                if (strength < 4) printf("Weak password\n");
                else if (strength < 6) printf("Moderate password\n");
                else printf("Strong password\n");
                wait_for_user();
                break;
                
            case 7:
                printf("Enter the file path to upload to VirusTotal: ");
            	fgets(input_file, sizeof(input_file), stdin);
            	strtok(input_file, "\n"); // Remove trailing newline
            	upload_file_to_virustotal(input_file);
                wait_for_user();
                break;
            case 8:
                printf("Enter the filename to analyze: ");
                scanf("%s", filename);
                analyze_file(filename);
                wait_for_user();
                break;
                
            case 9:
                system_security_check();
                wait_for_user();
                break;
                
            case 10:
                printf("Enter the input file path to compress: ");
                fgets(input_file, sizeof(input_file), stdin);
                strtok(input_file, "\n");  // Remove newline
                compress_file(input_file, output_dir);
                wait_for_user();
                break;
                
            case 11:
                printf("Enter the ZIP file path to decompress: ");
                fgets(input_file, sizeof(input_file), stdin);
                strtok(input_file, "\n");
                decompress_file(input_file, output_dir);
                wait_for_user();
                break;
            case 12:
    		printf("Enter input to analyze for SQL Injection: ");
    		getchar();
    		fgets(input, BUFFER_SIZE, stdin);
    		input[strcspn(input, "\n")] = 0;
    		sql_injection_test(input);
    		wait_for_user();
    		break;
            case 0:
                printf("Exiting the program. Goodbye!\n");
                exit(EXIT_SUCCESS);
            // Add cases for other functionalities...
            default:
                fprintf(stderr, "Error: Invalid choice. Please try again.\n");
        }
    }
    return 0;
}
