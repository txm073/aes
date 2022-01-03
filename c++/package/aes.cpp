// High level functions

// Full encryption function
std::string encrypt(std::string stringData, std::string password, std::string outputMode = "hex", int rlevel = 0) {
    int padding = 16 - (stringData.length() % 16); 
    std::string dtype = hex(1), enc = "", output = "";
    // Encrypt password with itself to validate upon decryption
    if (password != "") {
        if (!rlevel) {
            enc = encrypt(password, password, "hex", 1);
        }
    }
    // Prepend headers / metadata to the output
    output = output + hex(padding) + dtype + enc + (!rlevel ? DELIMITER : "");
    VECTOR data = pad(toIntegerArray(stringData));
    MATRIX key = createMatrix(deriveKey(password));
    std::vector<MATRIX> roundKeys = expandKey(key);
    // Perform a Rijndael cipher on each block of data and convert to hex digest
    for (int i = 0; i < data.size(); i += 16) {
        MATRIX block = createMatrix(slice(data, i, i + 15));
        MATRIX cipherBlock = rijndaelCipher(block, roundKeys);
        output += reformat(cipherBlock);
    }
    // Encode to base-64 if necessary
    if (outputMode == "base64") {
        return b64::encode(output);
    }
    return output;
}   

// Entire decryption process 
std::string decrypt(std::string stringData, std::string password = "", std::string key = "", std::string inputMode = "hex", int rlevel = 0) {
    if (inputMode == "base64") {
        stringData = b64::decode(stringData);
    }
    // Recreate key and round keys
    VECTOR keyVector = {};
    if (password != "") {
        keyVector = deriveKey(password);
    } else {
        keyVector = toIntegerArray(key);
    }
    std::vector<MATRIX> roundKeys = expandKey(createMatrix(keyVector));
    // Split message into headers and body text
    std::string headers = "";
    if (!rlevel) {
        for (int i = 0; i < stringData.length(); i += 2) {
            if (stringData.substr(i, 2) == DELIMITER) {
                headers = stringData.substr(0, i); 
                stringData = stringData.substr(i + 2, stringData.length() - (i + 2));
                break;
            }
        }
    } else {
        headers = stringData;
    }
    // Parse message headers
    int padding = denary(headers.substr(0, 2));
    int dtype = denary(headers.substr(2, 4));
    if (password != "" && headers.length() > 4) {
        std::string encryptedPassword = headers.substr(4, headers.length() - 4);
        if (!rlevel) {
            std::string decryptedPassword = decrypt(encryptedPassword, password, "", "hex", 1);
            if (decryptedPassword != password) {
                throw std::runtime_error("Invalid password!");
            }
        }
    }
    // Convert hex digest into base-10 integer array
    VECTOR data = {};
    for (int i = 0; i < stringData.length(); i += 2) {
        data.push_back(denary(stringData.substr(i, 2)));
    }
    std::string output = "";
    if (rlevel) {
        data = slice(data, 2, data.size() - 1);
    }
    // Perform inverse Rijndael cipher on each block of data
    for (int i = 0; i < data.size(); i += 16) {
        MATRIX block = createMatrix(slice(data, i, i + 15));
        MATRIX plainTextBlock = rijndaelInverse(block, roundKeys);
        output += toPlainText(plainTextBlock);
    }
    if (padding) {
        output = output.substr(0, output.length() - padding);
    }
    return output;
}

// Encrypt the contents of a file using a specific password
void encryptFile(std::string fileName, std::string password, int lineLength = 80) {
    std::string contents = readFile(fileName, false);
    std::string enc = encrypt(contents, password);
    writeToFile(fileName, enc, lineLength);
}

// Decrypt an encrypted file using a specific password
void decryptFile(std::string fileName, std::string password) {
    std::string enc = readFile(fileName, true);
    std::string decrypted = decrypt(enc, password);
    writeToFile(fileName, decrypted, -1);   
}
