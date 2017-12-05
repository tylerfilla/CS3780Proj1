/*
 * Tyler Filla
 * CS 3780
 * Project 1
 * Password Crack Executable
 */

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <unistd.h>

#include <openssl/md5.h>
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

void split_passwd_line(const std::string& str, std::vector<std::string>& out)
{
    auto last_delim_it = str.cbegin() - 1;
    for (auto i = str.cbegin(); i != str.cend(); ++i)
    {
        if (i == str.cend() - 1)
        {
            out.emplace_back(last_delim_it + 1, i + 1);
        }
        else if (*i == ':')
        {
            out.emplace_back(last_delim_it + 1, i);
            last_delim_it = i;
        }
    }
}

static int crack_passwdmd5(std::ifstream& file, const std::string& start, unsigned int num)
{
    std::cout << "Attempting to crack MD5 password file\n";
    std::cout << "Loading accounts into memory...";
    std::cout.flush();

    // A map of accounts from password hashes to sets of usernames
    std::unordered_map<std::string, std::unordered_set<std::string>> accounts;

    // Load all accounts from file into memory
    unsigned int num_accounts = 0;
    for (std::string line; std::getline(file, line);)
    {
        std::vector<std::string> line_parts;
        split_passwd_line(line, line_parts);

        if (line_parts.size() != 2)
            continue;

        auto username = line_parts[0];
        auto password_md5 = line_parts[1];

        if (accounts.find(password_md5) == accounts.end())
        {
            accounts[password_md5] = { username };
        }
        else
        {
            accounts[password_md5].insert(username);
        }

        num_accounts++;
    }

    std::cout << "done!\n";
    std::cout << accounts.size() << " unique passwords among " << num_accounts << " accounts\n";

    // Crack the passwords!
    std::string password = start;
    for (int a = 0; a < num; ++a)
    {
        auto password_md5 = hash_password_md5(password);
        if (accounts.find(password_md5) != accounts.end())
        {
            std::cout << "MATCHED: \"" << password << "\" (MD5: " + password_md5 + ")\n";

            auto usernames = accounts[password_md5];
            for (auto u = usernames.cbegin(); u != usernames.cend(); ++u)
            {
                std::cout << " -> " << *u << "\n";
            }
        }

        // Increment one decimal place with carry logic and zeroes
        // Reserve an extra character to prevent reallocation during iteration
        password.reserve(password.length() + 1);
        for (auto i = password.rbegin(); i != password.rend(); ++i)
        {
            if (*i == '9')
            {
                *i = '0';

                // Prepend a zero to satisfy carry, if necessary
                if (i == password.rend() - 1)
                {
                    password = '0' + password;
                }
            }
            else
            {
                // Increment numeral and stop
                ++*i;
                break;
            }
        }
    }

    return 0;
}

static int crack_passwdSHA256(std::ifstream& file, const std::string& start, unsigned int num)
{
    std::cout << "Attempting to crack SHA256 password file\n";
    std::cout << "Loading accounts into memory...";
    std::cout.flush();

    // A map of accounts from password hashes to sets of usernames
    std::unordered_map<std::string, std::unordered_set<std::string>> accounts;

    // Load all accounts from file into memory
    unsigned int num_accounts = 0;
    for (std::string line; std::getline(file, line);)
    {
        std::vector<std::string> line_parts;
        split_passwd_line(line, line_parts);

        if (line_parts.size() != 2)
            continue;

        auto username = line_parts[0];
        auto password_sha256 = line_parts[1];

        if (accounts.find(password_sha256) == accounts.end())
        {
            accounts[password_sha256] = { username };
        }
        else
        {
            accounts[password_sha256].insert(username);
        }

        num_accounts++;
    }

    std::cout << "done!\n";
    std::cout << accounts.size() << " unique passwords among " << num_accounts << " accounts\n";

    // Crack the passwords!
    std::string password = start;
    for (int a = 0; a < num; ++a)
    {
        auto password_sha256 = hash_password_sha256(password);
        if (accounts.find(password_sha256) != accounts.end())
        {
            std::cout << "MATCHED: \"" << password << "\" (SHA256: " + password_sha256 + ")\n";

            auto usernames = accounts[password_sha256];
            for (auto u = usernames.cbegin(); u != usernames.cend(); ++u)
            {
                std::cout << " -> " << *u << "\n";
            }
        }

        // Increment one decimal place with carry logic and zeroes
        // Reserve an extra character to prevent reallocation during iteration
        password.reserve(password.length() + 1);
        for (auto i = password.rbegin(); i != password.rend(); ++i)
        {
            if (*i == '9')
            {
                *i = '0';

                // Prepend a zero to satisfy carry, if necessary
                if (i == password.rend() - 1)
                {
                    password = '0' + password;
                }
            }
            else
            {
                // Increment numeral and stop
                ++*i;
                break;
            }
        }
    }

    return 0;
}

static int crack_passwdSHA256salt(std::ifstream& file, const std::string& start, unsigned int num)
{
    std::cout << "Attempting to crack salted SHA256 password file\n";
    std::cout << "Loading accounts into memory...";
    std::cout.flush();

    // A map of accounts from pairs of usernames and salts to password hashes
    std::list<std::tuple<std::string, std::string, std::string>> accounts;

    // Load all accounts from file into memory
    for (std::string line; std::getline(file, line);)
    {
        std::vector<std::string> line_parts;
        split_passwd_line(line, line_parts);

        if (line_parts.size() != 3)
            continue;

        auto username = line_parts[0];
        auto salt = line_parts[1];
        auto password_sha256 = line_parts[2];

        accounts.push_back(std::make_tuple(username, salt, password_sha256));
    }

    std::cout << "done!\n";
    std::cout << accounts.size() << " accounts\n";

    for (auto b = accounts.cbegin(); b != accounts.cend(); ++b)
    {
        std::string password = start;
        for (int a = 0; a < num; ++a)
        {
            auto password_sha256 = hash_password_sha256(std::get<1>(*b) + password);
            if (password_sha256 == std::get<2>(*b))
            {
                std::cout << "MATCHED: \"" << password << "\" (SHA256: " + password_sha256 + ")\n";
                std::cout << " -> " << std::get<0>(*b) << "\n";
            }

            // Increment one decimal place with carry logic and zeroes
            // Reserve an extra character to prevent reallocation during iteration
            password.reserve(password.length() + 1);
            for (auto i = password.rbegin(); i != password.rend(); ++i)
            {
                if (*i == '9')
                {
                    *i = '0';

                    // Prepend a zero to satisfy carry, if necessary
                    if (i == password.rend() - 1)
                    {
                        password = '0' + password;
                    }
                }
                else
                {
                    // Increment numeral and stop
                    ++*i;
                    break;
                }
            }
        }
    }

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: crack <file> [start] [num]\n";
        std::cout << "Attempt to crack passwords from the given password file\n";
        std::cout << "Generate num password attempts starting with start\n";
        return 0;
    }

    // Get file argument
    auto file_path = argv[1];

    // Get start argument
    auto start = "0";
    if (argc >= 3)
    {
         start = argv[2];
    }

    // Get num argument
    auto num = 100000;
    if (argc >= 4)
    {
         num = std::strtoul(argv[3], nullptr, 0);
    }

    // Get file name
    auto file_name = basename(file_path);

    // Open password file
    std::ifstream file;
    file.open(file_path);

    // Run the file-appropriate cracking function
    if (std::strcmp(file_name, "passwdmd5") == 0)
    {
        return crack_passwdmd5(file, start, num);
    }
    else if (std::strcmp(file_name, "passwdSHA256") == 0)
    {
        return crack_passwdSHA256(file, start, num);
    }
    else if (std::strcmp(file_name, "passwdSHA256salt") == 0)
    {
        return crack_passwdSHA256salt(file, start, num);
    }
    else
    {
        std::cerr << "Cannot determine password hash type from file\n";
        return 1;
    }

    file.close();

    return 0;
}
