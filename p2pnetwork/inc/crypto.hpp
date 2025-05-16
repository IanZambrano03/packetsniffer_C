#pragma once
#include <array>
#include <string>
#include <filesystem>
#include <vector>
#include <fstream>
#include <iostream>
#include <sodium.h>

static_assert(crypto_aead_aes256gcm_NPUBBYTES == 12, "Nonce size mismatch");

using SignPublicKey = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>;
using SignPrivateKey = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>;
using EncryptPublicKey = std::array<unsigned char, crypto_kx_PUBLICKEYBYTES>;
using EncryptPrivateKey = std::array<unsigned char, crypto_kx_SECRETKEYBYTES>;

bool initialize() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed.\n";
        return false;
    }
    return true;
}

bool generate_signing_keypair(SignPublicKey& publicKey, SignPrivateKey& privateKey) noexcept {
    return crypto_sign_keypair(publicKey.data(), privateKey.data()) == 0;
}

bool generate_encryption_keypair(EncryptPublicKey& publicKey, EncryptPrivateKey& privateKey) {
    return crypto_kx_keypair(publicKey.data(), privateKey.data()) == 0;
}

std::array<unsigned char, 32> derive_aes_key(const EncryptPrivateKey& priv) {
    std::array<unsigned char, 32> aes_key;
    crypto_generichash(aes_key.data(), aes_key.size(), priv.data(), priv.size(), nullptr, 0);
    return aes_key;
}

// Helper function to read an entire file into a vector
std::vector<unsigned char> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Could not open input file.");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read input file.");
    }

    return buffer;
}

bool encrypt_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const std::array<unsigned char, 32>& key
) noexcept {
    try {
        const std::vector<unsigned char> plaintext = read_file(input_path);

        std::array<unsigned char, crypto_aead_aes256gcm_NPUBBYTES> nonce;
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
        unsigned long long ciphertext_len;

        int result = crypto_aead_aes256gcm_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0, // additional data
            nullptr, nonce.data(), key.data()
        );

        if (result != 0) {
            std::cerr << "Encryption failed.\n";
            return false;
        }

        std::ofstream out_file(output_path, std::ios::binary);
        if (!out_file) {
            std::cerr << "Failed to open output file\n";
            return false;
        }

        out_file.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
        out_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);

        if (!out_file) {
            std::cerr << "Failed to write encrypted data\n";
            return false;
        }

        sodium_memzero(const_cast<unsigned char*>(plaintext.data()), plaintext.size());
        return true;

    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << '\n';
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return false;
    } catch (...) {
        std::cerr << "Unknown error during encryption\n";
        return false;
    }
}
