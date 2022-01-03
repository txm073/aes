// Find a value from a lookup table
int lookup(int i, MATRIX table = SUBBYTES) {
    int x = i / 16, y = i % 16;
    return table[x][y];
}

// Find the table co-ordinates from a value (inverse for sub bytes round step)
int inverseLookup(int n, MATRIX table = SUBBYTES) {
    for (int i = 0; i < table.size(); ++i) {
        for (int j = 0; j < table[i].size(); ++j) {
            if (table[i][j] == n) {
                return i * 16 + j;
            }
        }
    }
    return -1;
}

// Mixcols transformation function for 2 elements
int transform(int i, int j) {
    switch (j) {
        case 1:
            return i;
        case 2:
            return ((i << 1) ^ 0x1b) % 256;
        case 3:
            return transform(i, 2) ^ i; 
        case 9:
            return transform(transform(transform(i, 2), 2), 2) ^ i;
        case 11:
            return transform(transform(transform(i, 2), 2) ^ i, 2) ^ i;
        case 13:
            return transform(transform(transform(i, 2) ^ i, 2), 2) ^ i;
        case 14:
            return transform(transform(transform(i, 2) ^ i, 2) ^ i, 2);
        default: 
            return -1;
    }
}

// Byte substitution from a lookup table
MATRIX subBytes(MATRIX data, bool inverse = false) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            if (!inverse) {
                data[i][j] = lookup(data[i][j]);
            } else {
                data[i][j] = inverseLookup(data[i][j]);
            }
        }
    }
    return data;
}

// Permutation by performing an element-wise shift for each row by it's index
MATRIX shiftRows(MATRIX data, bool inverse = false) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < (inverse ? 4 - i : i); ++j) {
            data[i].push_back(data[i][0]);
            data[i].erase(data[i].begin());
        }
    }
    return data;
}

// Mixcolumns matrix multiplication function inside a Galois Field
MATRIX mixColumns(MATRIX data, bool inverse = false) {
    MATRIX mat = (inverse ? MIXCOLS_INV : MIXCOLS), output = EMPTY;
    for (int i = 0; i < 4; ++i) {
        VECTOR row = mat[i];
        for (int j = 0; j < 4; ++j) {
            VECTOR col = getColumn(data, j), products = {};
            for (int n = 0; n < 4; ++n) {
                products.push_back(transform(col[n], row[n]));
            }
            output[i][j] = xorSum(products);
        }
    }
    return output;
}

// Add the generated round key to the matrix using column-wise XOR gates
MATRIX addRoundKey(MATRIX data, MATRIX roundKey) {
    for (int i = 0; i < 4; ++i) {
        data = setColumn(data, xorVector(getColumn(data, i), getColumn(roundKey, i)), i);
    }
    return data;
}

// Perform 1 AES round
MATRIX round(MATRIX data, MATRIX roundKey, bool doMixCols = true) {
    data = subBytes(data);
    data = shiftRows(data);
    if (doMixCols) {
        data = mixColumns(data);
    }
    data = addRoundKey(data, roundKey);
    return data;
}

// Perform 1 inverse AES round
MATRIX roundInverse(MATRIX data, MATRIX roundKey, bool doMixCols = true) {
    data = addRoundKey(data, roundKey);
    if (doMixCols) {
        data = mixColumns(data, true);
    }
    data = shiftRows(data, true);
    data = subBytes(data, true);
    return data;
}

// Perform the Rijndael Cipher (AES) on a 128-bit block of data
MATRIX rijndaelCipher(MATRIX data, std::vector<MATRIX> roundKeys) {
    data = addRoundKey(data, roundKeys[0]);
    for (int i = 1; i < ROUNDS + 1; ++i) {
        bool doMixCols = (i != ROUNDS);
        data = round(data, roundKeys[i], doMixCols);    
    }
    return data;
} 

// Reconstruct the original data from a 128-bit block of cipher text (reverse Rijndael Cipher)
MATRIX rijndaelInverse(MATRIX data, std::vector<MATRIX> roundKeys) {
    for (int i = 1; i < ROUNDS + 1; ++i) {
        bool doMixCols = (i != 1);
        data = roundInverse(data, roundKeys[(ROUNDS - i) + 1], doMixCols);
    }
    data = addRoundKey(data, roundKeys[0]);
    return data;
}
