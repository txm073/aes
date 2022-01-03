MATRIX generateRoundKey(MATRIX prevKey, int roundNum) {
    MATRIX output = EMPTY;
    
    // Calcluate first column with shift and sub bytes
    VECTOR col = getColumn(prevKey, 3);
    VECTOR firstCol = getColumn(prevKey, 0);
    col.push_back(col[0]);
    col.erase(col.begin());
    for (int i = 0; i < 4; ++i) {
        int value = col[i];
        col[i] = SUBBYTES[value / 16][value % 16];
        firstCol[i] = (firstCol[i] ^ col[i] ^ ROUNDCONST[roundNum][i]);
    }

    VECTOR colResultant = firstCol;
    output = setColumn(output, colResultant, 0);
    for (int i = 1; i < 4; ++i) {
        VECTOR col = getColumn(prevKey, i);
        colResultant = xorVector(col, colResultant);
        output = setColumn(output, colResultant, i);
    }
    return output;
} 

std::vector<MATRIX> expandKey(MATRIX key) {
    std::vector<MATRIX> roundKeys = {key,};
    for (int i = 0; i < ROUNDS; ++i) {
        MATRIX roundKey = generateRoundKey(roundKeys[i], i);
        roundKeys.push_back(roundKey);
    }
    return roundKeys;
}

VECTOR deriveKey(std::string password = "") {
    VECTOR output = {};
    if (password != "") {
        std::string hexDigest = picosha2::hash256_hex_string(password);
        for (int i = 0; i < hexDigest.length(); i += 4) {
            output.push_back(denary(hexDigest.substr(i, 2)) ^ denary(hexDigest.substr(i + 2, 2)));
        }
    }
    return output;
}