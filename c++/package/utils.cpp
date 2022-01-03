// Pad the data to be divisible by 16
VECTOR pad(VECTOR vec) {
    int padding = 16 - (vec.size() % 16);
    if (padding == 16) {
        return vec;
    }
    for (int i = 0; i < padding; ++i) {
        vec.push_back(vec[i]);
    }
    return vec;
}

// Slice a vector into a subvector

VECTOR slice(VECTOR &v, int m, int n) {
    VECTOR vec = {};
    std::copy(v.begin() + m, v.begin() + n + 1, std::back_inserter(vec));
    return vec;
}

// Utility function to print a matrix to the console
void printMatrix(MATRIX mat) {
    std::cout << "\n";
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            std::cout << mat[i][j] << " ";
        }
        std::cout << "\n";
    }
}

// Utility function to print a vector to the console
void printVector(VECTOR vec) {
    std::cout << "\n";
    for (int i : vec) std::cout << i << " ";
}

// Create a 4x4 column-wise matrix from a 16x1 array
MATRIX createMatrix(VECTOR vec) {
    MATRIX mat = EMPTY;
    assert(vec.size() == 16);
    for (int i = 0; i < 16; ++i) {
        int x = i / 4, y = i % 4;
        mat[y][x] = vec[i]; // Column-wise
    }
    return mat;
}

// Replace 10-16 with A-F
char intToHexChar(int i) {
    if (0 <= i && i <= 9) {
        return char(i + 48); 
    }
    return char(i + 55);
}

// Replace A-F with 10-16
int hexCharToInt(char c) {
    int asciiValue = int(c);
    if (65 <= asciiValue && asciiValue <= 71) {
        return asciiValue - 55;
    } else if (97 <= asciiValue && asciiValue <= 103) {
        return asciiValue - 87;
    } else {
        return asciiValue - 48;
    }
}

// Convert an 8 bit decimal integer to a 2-char hexadecimal digit
std::string hex(int i) {
    int bit1 = i / 16, bit2 = i % 16;
    return std::string(1, intToHexChar(bit1)) + std::string(1, intToHexChar(bit2));
}

// Convert a 2-char hexadecimal string to an 8-bit decimal integer
int denary(std::string hexString) {
    return (16 * hexCharToInt(hexString[0])) + hexCharToInt(hexString[1]);
}

// Returns elements in a specific column of a 4x4 matrix
VECTOR getColumn(MATRIX mat, int col) {
    VECTOR output = {};
    for (int i = 0; i < 4; ++i) {
        output.push_back(mat[i][col]);
    }
    return output;  
}

// Set a column of a 4x4 matrix as a 1x4 vector
MATRIX setColumn(MATRIX mat, VECTOR vec, int col) {
    for (int i = 0; i < 4; ++i) {
        mat[i][col] = vec[i];
    } 
    return mat;
}

// Convert a matrix into a hex digest (hexadecimal string)
std::string reformat(MATRIX data) {
    std::string output = "";
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            output += hex(data[j][i]);
        }
    }
    return output;
}

// Convert a string to an integer array 
VECTOR toIntegerArray(std::string str) {
    VECTOR output = {};
    for (char c : str) {
        output.push_back(int(c));
    }
    return output;
}

// Convert an integer array to ASCII characters
std::string toPlainText(VECTOR vec) {
    std::string output = "";
    for (int i : vec) {
        output += char(i);
    }
    return output;
}

// Convert a 4x4 matrix of integers to ASCII characters
std::string toPlainText(MATRIX mat) {
    std::string output = "";
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            output += char(mat[j][i]);
        }
    }
    return output;
} 

// XOR gate for each element in two vectors
VECTOR xorVector(VECTOR vec1, VECTOR vec2) {
    VECTOR output = {};
    assert(vec1.size() == vec2.size());
    for (int i = 0; i < vec1.size(); ++i) {
        output.push_back(vec1[i] ^ vec2[i]);
    }
    return output;
}

// Cumulative XOR function of an array (not reversible)
int xorSum(VECTOR vec) {
    int output = vec[0];
    for (int i = 1; i < vec.size(); ++i) {
        output ^= vec[i];
    }
    return output;
}

// Read the contents of a binary or text file
std::string readFile(std::string fileName, bool concatenateLines = true) {
    std::ifstream inputFile(fileName, std::ios::binary);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open file!");
    }
    std::string contents = "";
    if (concatenateLines) {
        std::string line = "";
        while (std::getline(inputFile, line)) {
            contents += line;
        }
    } else {
        char ch;
        while (inputFile >> std::noskipws >> ch) {
            contents += ch;
        }
    }
    inputFile.close();
    return contents;
}

// Writes text or binary strings to a file
void writeToFile(std::string fileName, std::string contents, int lineLength = 80) {
    std::ofstream outputFile(fileName, std::ios::binary);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Failed to open file!");        
    }
    for (int i = 1; i < contents.length() + 1; ++i) { 
        if (i % lineLength == 0 && lineLength != -1) {
            outputFile.put('\n');
        }
        outputFile.put(contents[i - 1]);
    }
    outputFile.close();
}