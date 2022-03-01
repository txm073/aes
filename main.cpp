#include <string>
#include <vector>
#include <iostream>
#include <regex>
//#include "c++/aes128.cpp"

std::vector<std::string> split(std::string str)
{
    std::vector<std::string> words;
    std::regex rgx("[^\\s\"']+|\"([^\"]*)\"|'([^']*)'");
    std::sregex_token_iterator iter(str.begin(), str.end(), rgx, -1);
    std::sregex_token_iterator end;
    while (iter != end)
    {
        // std::cout << "S43:" << *iter << std::endl;
        words.push_back(*iter);
        ++iter;
    }
    return words;
}

int main(int argc, char **argv)
{
    std::string argString = "";
    for (int i = 0; i < argc; ++i)
    {
        argString += (std::string(argv[i]) + (i + 1 != argc ? " " : ""));
    }
    std::vector<std::string> words = split(argString);
    for (std::string s : words)
        std::cout << s << " ";
    return 0;
}