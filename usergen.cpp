/*
 * Tyler Filla
 * CS 3780
 * Project 1
 * User Generator Executable
 */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <utility>

#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

std::string hash_password_md5(std::string password)
{
    std::stringstream out_ss;
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(&password[0]), password.length(), hash);
    out_ss << std::hex;
    for (auto i = std::begin(hash); i != std::end(hash); ++i)
    {
        out_ss << static_cast<int>(*i);
    }
    return out_ss.str();
}

std::string hash_password_sha256(std::string password)
{
    std::stringstream out_ss;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(&password[0]), password.length(), hash);
    out_ss << std::hex;
    for (auto i = std::begin(hash); i != std::end(hash); ++i)
    {
        out_ss << static_cast<int>(*i);
    }
    return out_ss.str();
}

std::pair<std::string, std::string> hash_password_salted_sha256(std::string password)
{
    // Generate "secure" salt value
    unsigned char salt[4];
    RAND_bytes(salt, sizeof(salt));
    std::stringstream out_salt_ss;
    out_salt_ss << std::hex;
    for (auto i = std::begin(salt); i != std::end(salt); ++i)
    {
        out_salt_ss << static_cast<int>(*i);
    }
    auto out_salt = out_salt_ss.str();

    // Generate salted hash
    auto out_hash = hash_password_sha256(out_salt + password);

    // Return both
    return std::make_pair(out_salt, out_hash);
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "Usage: usergen <len> <num>\n";
        std::cout << "Generate num accounts with passwords of length len\n";
        return 0;
    }

    // Read desired length of passwords
    unsigned int len = atoi(argv[1]);

    // Read desired number of accounts
    unsigned int num = atoi(argv[2]);

    // Valid characters for passwords
    char password_chars[] = "0123456789";

    // Seed rand() RNG with current Unix time
    std::srand(std::chrono::system_clock::now().time_since_epoch().count());

    for (unsigned int i = 0; i < num; ++i)
    {
        // Generate username
        std::stringstream username_ss;
        username_ss << "username";
        username_ss << i;
        auto username = username_ss.str();

        // Generate password
        std::string password(len, '\0');
        std::generate_n(password.begin(), len, [password_chars]()
        {
            // rand() is good enough for this project
            return password_chars[std::rand() % 10];
        });

        std::cout << username << ", " << password << "\n";

        // Do MD5 hash
        std::ofstream passwd_file_md5;
        passwd_file_md5.open("passwdmd5", std::ofstream::out | std::ofstream::app);
        passwd_file_md5 << username << ":" << hash_password_md5(password) << "\n";
        passwd_file_md5.close();

        // Do SHA256 hash
        std::ofstream passwd_file_sha256;
        passwd_file_sha256.open("passwdSHA256", std::ofstream::out | std::ofstream::app);
        passwd_file_sha256 << username << ":" << hash_password_sha256(password) << "\n";
        passwd_file_sha256.close();

        // Do salted SHA256 hash
        auto salt_hash = hash_password_salted_sha256(password);
        std::ofstream passwd_file_salted_sha256;
        passwd_file_salted_sha256.open("passwdSHA256salt", std::ofstream::out | std::ofstream::app);
        passwd_file_salted_sha256 << username << ":" << salt_hash.first << ":" << salt_hash.second << "\n";
        passwd_file_salted_sha256.close();
    }

    return 0;
}

