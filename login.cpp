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
#include <stdexcept>
#include <string>
#include <utility>

#include <openssl/md5.h>

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

static int do_log_in()
{
    // Prompt for user credentials
    auto credentials = prompt_credentials();
    auto username = credentials.first;
    auto password = credentials.second;

    return 0;
}

static int do_register()
{
    // Prompt for user credentials
    auto credentials = prompt_credentials();
    auto username = credentials.first;
    auto password = credentials.second;

    //
    // Hashing
    //

    // Hash password with MD5
    unsigned char password_md5[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*) &password[0], password.length(), &password_md5[0]);

    //
    // Output
    //

    // Append to MD5 hash file
    std::ofstream passwd_file_md5;
    passwd_file_md5.open("passwdmd5", std::ofstream::out | std::ofstream::app);
    passwd_file_md5 << username << ":" << std::hex;
    for (auto i = std::begin(password_md5); i != std::end(password_md5); ++i)
    {
        passwd_file_md5 << static_cast<int>(*i);
    }
    passwd_file_md5 << "\n";
    passwd_file_md5.close();

    // Append to SHA256 hash file
    // FIXME: Write this

    // Append to salted SHA256 hash file
    // FIXME: Write this

    return 0;
}

int main(int argc, char* argv[])
{
    // Get chosen user action
    auto choice = present_menu();

    // Build a wall
    std::cout << "\n================================================================================\n\n";

    // Handle chosen user action
    switch (choice)
    {
    case menu_choice::LOG_IN:
        return do_log_in();
    case menu_choice::REGISTER:
        return do_register();
    }

    return 1;
}

