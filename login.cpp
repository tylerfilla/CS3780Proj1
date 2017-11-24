/*
 * Tyler Filla
 * CS 3780
 * Project 1
 * Login Executable
 */

#include <iostream>
#include <stdexcept>
#include <string>

enum class menu_choice
{
    LOG_IN,
    REGISTER
};

menu_choice present_menu()
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

int main(int argc, char* argv[])
{
    return static_cast<int>(present_menu());
}

