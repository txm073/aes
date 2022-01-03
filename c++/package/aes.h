#ifndef aes
#define aes

#include <vector>
#include <string>
#include <cassert>
#include <algorithm>
#include <regex>
#include <iostream>
#include <iterator>
#include <cmath>
#include <stdexcept>
#include <fstream>

#include "constants.h"
#include "picosha2.h"
#include "utils.cpp"
#include "cipher.cpp"
#include "derive.cpp"
#include "b64.cpp"
#include "aes.cpp"

std::string encrypt(std::string stringData, std::string password, std::string outputMode = "hex", int rlevel = 0);
std::string decrypt(std::string stringData, std::string password = "", std::string key = "", std::string inputMode = "hex", int rlevel = 0);
void encryptFile(std::string fileName, std::string password, int lineLength = 80);
void decryptFile(std::string fileName, std::string password);

#endif