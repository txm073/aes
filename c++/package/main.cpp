#include "aes.h"

void input(std::string msg, std::string var) {
    std::cout << msg;
    std::getline(std::cin, var);
}

int main(int argc, char** argv) {
    for (int i = 0; i < argc; ++i) {
        std::cout << argv[i] << std::endl;
    }
    if (argc != 3 || argc != 4) {
        return 1;
    }
    std::string mode = argv[1], data = "";
    bool file;
    if (argv[2] == "-f" || argv[2] == "-F") {
        data = argv[3];
        file = true;
    } else {
        data = argv[2];
        file = false;
    }
    std::string password;
    if (argv[1] == "encrypt") {
        input("Create a password: ", password);
        while (password == "") {
            input("Create a password: ", password);
        }
        if (file) {
            encryptFile(data, password);
        } else {
            std::cout << encrypt(data, password);
        }
    }
    if (argv[1] == "decrypt") {
        input("Enter decryption password: ", password);
        while (password == "") {
            input("Enter decryption password: ", password);
        }
        if (file) {
            decrypt(data, password);
        } else {
            std::cout << decrypt(data, password);
        }
    }
    return 0;
    /*
    std::string inputFile, password, passwordVerify;
    input("Input a file path: ", inputFile);
    input("Create an encryption password: ", password);
    input("Confirm your password: ", passwordVerify);

    while (password != passwordVerify) {
        input("Passwords do not match, please try again: ", passwordVerify);
    }
    std::cout << "Encrypting file..." << "\n";
    encryptFile(inputFile, password);

    std::string decryptPassword;
    input("Enter password for decryption: ", decryptPassword);
    */
}