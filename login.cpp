/*
 * Tyler Filla
 * CS 3780
 * Project 1
 * Login Executable
 */

#include <cstdlib>
#include <cctype>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

enum class menu_choice
{
    LOG_IN,
    REGISTER
};

static menu_choice present_menu()
{
    while (true)
    {
        std::cout << "Available actions:\n";
        std::cout << "  1. Log in\n";
        std::cout << "  2. Register\n\n";
        std::cout << "> ";

        std::string choice_str;
        std::getline(std::cin, choice_str);

        int choice = -1;
        try
        {
            choice = std::stoi(choice_str);
        }
        catch (const std::invalid_argument& einval)
        {
            std::cout << "ERROR: Input not integral\n\n";
            continue;
        }
        catch (const std::out_of_range& erange)
        {
            std::cout << "ERROR: Input out of range\n\n";
            continue;
        }

        switch (choice)
        {
        case 1:
            return menu_choice::LOG_IN;
        case 2:
            return menu_choice::REGISTER;
        default:
            std::cout << "ERROR: Unsupported action\n\n";
            continue;
        }
    }
}

static std::pair<std::string, std::string> prompt_credentials()
{
    std::string username;
    std::string conceal_pass_str;
    bool conceal_pass;
    std::string password;
    std::string::const_iterator pci;

    // Get username
ask_username:
    std::cout << "Username: ";
    std::getline(std::cin, username);

    if (username.empty())
        goto ask_username;

    // Ask whether to show password on terminal input
    // This requires a supported system and environment, but works on delmar
    std::cout << "Show password? (y/N) ";
    std::getline(std::cin, conceal_pass_str);

    // Determine if user wants to conceal the password
    conceal_pass = conceal_pass_str.compare("y") && conceal_pass_str.compare("Y");

    // Get password (with optional concealing)
ask_password:
    if (conceal_pass)
    {
        // Disable TTY echo
        std::system("stty -echo");
    }

    // Prompt for password text
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (password.empty())
        goto ask_password;

    // Ensure password is a decimal integer
    for (pci = password.cbegin(); pci != password.cend(); ++pci)
    {
        if (!std::isdigit(*pci))
        {
            std::cout << "ERROR: Password not integral\n";
            goto ask_password;
        }
    }

    if (conceal_pass)
    {
        // Re-enable TTY echo
        std::system("stty echo");

        // Supplement missing line break
        std::cout << "\n";
    }

    return std::make_pair(username, password);
}

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

static int do_log_in()
{
    // Prompt for user credentials
    auto credentials = prompt_credentials();
    auto username = credentials.first;
    auto password = credentials.second;

    // Do MD5 hash
    std::string password_md5 = hash_password_md5(password);

    // Check against MD5 password file
    std::ifstream passwd_file_md5;
    passwd_file_md5.open("passwdmd5");
    std::cout << "\n";
    for (std::string line; std::getline(passwd_file_md5, line);)
    {
        // If username matches
        if (line.find(username) == 0)
        {
            // DEBUG PRINT
            std::cout << "Matched username in passwdmd5!\n";

            // If password hash matches
            std::cout << "Expected hash: " << password_md5 << "\n";
            if (line.find(password_md5) == username.length() + 1)
            {
                std::cout << "Matched MD5 hash!\n";
            }
            else
            {
                std::cout << "Hashes don't match!\n";
            }

            break;
        }
    }
    passwd_file_md5.close();

    // Do SHA256 hash
    std::string password_sha256 = hash_password_sha256(password);

    // Check against SHA256 password file
    std::ifstream passwd_file_sha256;
    passwd_file_sha256.open("passwdSHA256");
    std::cout << "\n";
    for (std::string line; std::getline(passwd_file_sha256, line);)
    {
        // If username matches
        if (line.find(username) == 0)
        {
            // DEBUG PRINT
            std::cout << "Matched username in passwdSHA256!\n";

            // If password hash matches
            std::cout << "Expected hash: " << password_sha256 << "\n";
            if (line.find(password_sha256) == username.length() + 1)
            {
                std::cout << "Matched SHA256 hash!\n";
            }
            else
            {
                std::cout << "Hashes don't match!\n";
            }

            break;
        }
    }
    passwd_file_sha256.close();

    // Check against salted SHA256 password file
    std::ifstream passwd_file_salted_sha256;
    passwd_file_salted_sha256.open("passwdSHA256salt");
    std::cout << "\n";
    for (std::string line; std::getline(passwd_file_salted_sha256, line);)
    {
        // If username matches
        if (line.find(username) == 0)
        {
            // DEBUG PRINT
            std::cout << "Matched username in passwdSHA256salt!\n";

            // Inefficiently and dangerously extract the saved salt
            auto salt = line.substr(line.find(":") + 1);
            salt = salt.substr(0, salt.find(":"));
            std::cout << "Saved salt: " << salt << "\n";

            // Hash and compare passwords
            auto hash = hash_password_sha256(salt + password);
            std::cout << "Expected hash: " << hash << "\n";
            if (line.find(hash) == username.length() + salt.length() + 2)
            {
                std::cout << "Matched salted SHA256 hash!\n";
            }
            else
            {
                std::cout << "Hashes don't match!\n";
            }

            break;
        }
    }
    passwd_file_salted_sha256.close();

    return 0;
}

static int do_register()
{
    // Prompt for user credentials
    auto credentials = prompt_credentials();
    auto username = credentials.first;
    auto password = credentials.second;

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

    return 0;
}

int main(int argc, char* argv[])
{
    // Get chosen user action
    auto choice = present_menu();
    std::cout << "\n";

    // Handle chosen user action
    switch (choice)
    {
    case menu_choice::LOG_IN:
        std::cout << "Please log in below\n";
        return do_log_in();
    case menu_choice::REGISTER:
        std::cout << "Please register below\n";
        return do_register();
    }

    return 1;
}

