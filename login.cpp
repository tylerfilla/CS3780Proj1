/*
 * Tyler Filla
 * CS 3780
 * Project 1
 * Login Executable
 */

#include <cstdlib>
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

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
    // Get username
    std::cout << "Username: ";
    std::string username;
    std::getline(std::cin, username);

    // Ask whether to show password on terminal input
    // This requires a supported system and environment, but works on delmar
    std::cout << "Show password? (y/N) ";
    std::string conceal_pass_str;
    std::getline(std::cin, conceal_pass_str);

    bool conceal_pass = conceal_pass_str.compare("y")
            && conceal_pass_str.compare("Y");

    std::string password;
    std::string::const_iterator pci;

ask_password:
    if (conceal_pass)
    {
        // Disable TTY echo
        std::system("stty -echo");
    }

    // Prompt for password text
    std::cout << "Password: ";
    std::getline(std::cin, password);

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

