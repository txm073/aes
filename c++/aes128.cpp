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
#include <sstream>
#include <map>

namespace b64
{

    // All 64 printable characters in the base-64 alphabet
    static std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Maps an integer between 0-63 to a character in the base-64 alphabet
    static std::map<int, char> encodeMap = {};
    // Maps a character in the base-64 alphabet to an integer between 0-63
    static std::map<char, int> decodeMap = {};

    // Populate the encode-decode maps
    void table()
    {
        if (encodeMap.size())
        {
            return;
        }
        for (int i = 0; i < 64; i++)
        {
            encodeMap.insert(std::make_pair(i, chars[i]));
            decodeMap.insert(std::make_pair(chars[i], i));
        }
    };

    // Convert a base-10 integer to an n bit binary string
    std::string binary(int i, int bits)
    {
        std::string output;
        double value = pow(2.0, bits - 1);
        for (int j = 0; j < bits; j++)
        {
            if (value <= i)
            {
                i -= value;
                output += "1";
            }
            else
            {
                output += "0";
            }
            value /= 2;
        }
        return output;
    }

    // Convert a binary string to a base-10 integer
    int denary(std::string bin, int bits)
    {
        int output = 0;
        double value = pow(2.0, bits - 1);
        for (char c : bin)
        {
            if (c == '1')
            {
                output += value;
            }
            value /= 2;
        }
        return output;
    }

    // Encode a string of ASCII characters to a base-64 string
    std::string encode(std::string str)
    {
        table();
        std::string output = "", stream = "";
        int pad = 0;
        for (char c : str)
        {
            stream += binary(int(c), 8);
        }
        pad = 6 - (stream.length() % 6);
        if (pad != 6)
        {
            for (int i = 0; i < pad; i++)
                stream += '0';
        }
        for (int i = 0; i < stream.length(); i += 6)
        {
            std::string bit = stream.substr(i, 6);
            output += encodeMap[denary(bit, 6)];
        }
        if (pad != 6)
        {
            for (int i = 0; i < pad / 2; i++)
            {
                output += "=";
            }
        }
        return output;
    }

    // Decode a base-64 string to a string of ASCII characters
    std::string decode(std::string str)
    {
        table();
        std::smatch match;
        std::regex_search(str, match, std::regex("[^A-Za-z0-9\\/\\+\\=]"));
        if (match.length())
        {
            for (auto m : match)
            {
                throw std::runtime_error("Invalid character: '" + m.str() + "'");
            }
        }
        std::string stream = "", output = "";
        std::regex_search(str, match, std::regex("\\="));
        int pad = 2 * match.length();
        str = std::regex_replace(str, std::regex("\\="), "");
        for (char c : str)
        {
            stream += binary(decodeMap[c], 6);
        }
        if (pad)
        {
            stream = stream.substr(0, stream.length() - pad);
        }
        for (int i = 0; i < stream.length(); i += 8)
        {
            output += char(denary(stream.substr(i, i + 8), 8));
        }
        return output;
    }
}

#ifndef PICOSHA2_BUFFER_SIZE_FOR_INPUT_ITERATOR
#define PICOSHA2_BUFFER_SIZE_FOR_INPUT_ITERATOR \
    1048576 //=1024*1024: default is 1MB memory
#endif

namespace picosha2
{
    typedef unsigned long word_t;
    typedef unsigned char byte_t;

    namespace detail
    {
        inline byte_t mask_8bit(byte_t x) { return x & 0xff; }

        inline word_t mask_32bit(word_t x) { return x & 0xffffffff; }

        const word_t add_constant[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

        const word_t initial_message_digest[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                                  0xa54ff53a, 0x510e527f, 0x9b05688c,
                                                  0x1f83d9ab, 0x5be0cd19};

        inline word_t ch(word_t x, word_t y, word_t z) { return (x & y) ^ ((~x) & z); }

        inline word_t maj(word_t x, word_t y, word_t z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        inline word_t rotr(word_t x, std::size_t n)
        {
            assert(n < 32);
            return mask_32bit((x >> n) | (x << (32 - n)));
        }

        inline word_t bsig0(word_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }

        inline word_t bsig1(word_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

        inline word_t shr(word_t x, std::size_t n)
        {
            assert(n < 32);
            return x >> n;
        }

        inline word_t ssig0(word_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }

        inline word_t ssig1(word_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

        template <typename RaIter1, typename RaIter2>
        void hash256_block(RaIter1 message_digest, RaIter2 first, RaIter2 last)
        {
            assert(first + 64 == last);
            static_cast<void>(last); // for avoiding unused-variable warning
            word_t w[64];
            std::fill(w, w + 64, 0);
            for (std::size_t i = 0; i < 16; ++i)
            {
                w[i] = (static_cast<word_t>(mask_8bit(*(first + i * 4))) << 24) |
                       (static_cast<word_t>(mask_8bit(*(first + i * 4 + 1))) << 16) |
                       (static_cast<word_t>(mask_8bit(*(first + i * 4 + 2))) << 8) |
                       (static_cast<word_t>(mask_8bit(*(first + i * 4 + 3))));
            }
            for (std::size_t i = 16; i < 64; ++i)
            {
                w[i] = mask_32bit(ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) +
                                  w[i - 16]);
            }

            word_t a = *message_digest;
            word_t b = *(message_digest + 1);
            word_t c = *(message_digest + 2);
            word_t d = *(message_digest + 3);
            word_t e = *(message_digest + 4);
            word_t f = *(message_digest + 5);
            word_t g = *(message_digest + 6);
            word_t h = *(message_digest + 7);

            for (std::size_t i = 0; i < 64; ++i)
            {
                word_t temp1 = h + bsig1(e) + ch(e, f, g) + add_constant[i] + w[i];
                word_t temp2 = bsig0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = mask_32bit(d + temp1);
                d = c;
                c = b;
                b = a;
                a = mask_32bit(temp1 + temp2);
            }
            *message_digest += a;
            *(message_digest + 1) += b;
            *(message_digest + 2) += c;
            *(message_digest + 3) += d;
            *(message_digest + 4) += e;
            *(message_digest + 5) += f;
            *(message_digest + 6) += g;
            *(message_digest + 7) += h;
            for (std::size_t i = 0; i < 8; ++i)
            {
                *(message_digest + i) = mask_32bit(*(message_digest + i));
            }
        }

    } // namespace detail

    template <typename InIter>
    void output_hex(InIter first, InIter last, std::ostream &os)
    {
        os.setf(std::ios::hex, std::ios::basefield);
        while (first != last)
        {
            os.width(2);
            os.fill('0');
            os << static_cast<unsigned int>(*first);
            ++first;
        }
        os.setf(std::ios::dec, std::ios::basefield);
    }

    template <typename InIter>
    void bytes_to_hex_string(InIter first, InIter last, std::string &hex_str)
    {
        std::ostringstream oss;
        output_hex(first, last, oss);
        hex_str.assign(oss.str());
    }

    template <typename InContainer>
    void bytes_to_hex_string(const InContainer &bytes, std::string &hex_str)
    {
        bytes_to_hex_string(bytes.begin(), bytes.end(), hex_str);
    }

    template <typename InIter>
    std::string bytes_to_hex_string(InIter first, InIter last)
    {
        std::string hex_str;
        bytes_to_hex_string(first, last, hex_str);
        return hex_str;
    }

    template <typename InContainer>
    std::string bytes_to_hex_string(const InContainer &bytes)
    {
        std::string hex_str;
        bytes_to_hex_string(bytes, hex_str);
        return hex_str;
    }

    class hash256_one_by_one
    {
    public:
        hash256_one_by_one() { init(); }

        void init()
        {
            buffer_.clear();
            std::fill(data_length_digits_, data_length_digits_ + 4, 0);
            std::copy(detail::initial_message_digest,
                      detail::initial_message_digest + 8, h_);
        }

        template <typename RaIter>
        void process(RaIter first, RaIter last)
        {
            add_to_data_length(std::distance(first, last));
            std::copy(first, last, std::back_inserter(buffer_));
            std::size_t i = 0;
            for (; i + 64 <= buffer_.size(); i += 64)
            {
                detail::hash256_block(h_, buffer_.begin() + i,
                                      buffer_.begin() + i + 64);
            }
            buffer_.erase(buffer_.begin(), buffer_.begin() + i);
        }

        void finish()
        {
            byte_t temp[64];
            std::fill(temp, temp + 64, 0);
            std::size_t remains = buffer_.size();
            std::copy(buffer_.begin(), buffer_.end(), temp);
            temp[remains] = 0x80;

            if (remains > 55)
            {
                std::fill(temp + remains + 1, temp + 64, 0);
                detail::hash256_block(h_, temp, temp + 64);
                std::fill(temp, temp + 64 - 4, 0);
            }
            else
            {
                std::fill(temp + remains + 1, temp + 64 - 4, 0);
            }

            write_data_bit_length(&(temp[56]));
            detail::hash256_block(h_, temp, temp + 64);
        }

        template <typename OutIter>
        void get_hash_bytes(OutIter first, OutIter last) const
        {
            for (const word_t *iter = h_; iter != h_ + 8; ++iter)
            {
                for (std::size_t i = 0; i < 4 && first != last; ++i)
                {
                    *(first++) = detail::mask_8bit(
                        static_cast<byte_t>((*iter >> (24 - 8 * i))));
                }
            }
        }

    private:
        void add_to_data_length(word_t n)
        {
            word_t carry = 0;
            data_length_digits_[0] += n;
            for (std::size_t i = 0; i < 4; ++i)
            {
                data_length_digits_[i] += carry;
                if (data_length_digits_[i] >= 65536u)
                {
                    carry = data_length_digits_[i] >> 16;
                    data_length_digits_[i] &= 65535u;
                }
                else
                {
                    break;
                }
            }
        }
        void write_data_bit_length(byte_t *begin)
        {
            word_t data_bit_length_digits[4];
            std::copy(data_length_digits_, data_length_digits_ + 4,
                      data_bit_length_digits);

            // convert byte length to bit length (multiply 8 or shift 3 times left)
            word_t carry = 0;
            for (std::size_t i = 0; i < 4; ++i)
            {
                word_t before_val = data_bit_length_digits[i];
                data_bit_length_digits[i] <<= 3;
                data_bit_length_digits[i] |= carry;
                data_bit_length_digits[i] &= 65535u;
                carry = (before_val >> (16 - 3)) & 65535u;
            }

            // write data_bit_length
            for (int i = 3; i >= 0; --i)
            {
                (*begin++) = static_cast<byte_t>(data_bit_length_digits[i] >> 8);
                (*begin++) = static_cast<byte_t>(data_bit_length_digits[i]);
            }
        }
        std::vector<byte_t> buffer_;
        word_t data_length_digits_[4]; // as 64bit integer (16bit x 4 integer)
        word_t h_[8];
    };

    inline void get_hash_hex_string(const hash256_one_by_one &hasher,
                                    std::string &hex_str)
    {
        byte_t hash[32];
        hasher.get_hash_bytes(hash, hash + 32);
        return bytes_to_hex_string(hash, hash + 32, hex_str);
    }

    inline std::string get_hash_hex_string(const hash256_one_by_one &hasher)
    {
        std::string hex_str;
        get_hash_hex_string(hasher, hex_str);
        return hex_str;
    }

    namespace impl
    {
        template <typename RaIter, typename OutIter>
        void hash256_impl(RaIter first, RaIter last, OutIter first2, OutIter last2, int,
                          std::random_access_iterator_tag)
        {
            hash256_one_by_one hasher;
            // hasher.init();
            hasher.process(first, last);
            hasher.finish();
            hasher.get_hash_bytes(first2, last2);
        }

        template <typename InputIter, typename OutIter>
        void hash256_impl(InputIter first, InputIter last, OutIter first2,
                          OutIter last2, int buffer_size, std::input_iterator_tag)
        {
            std::vector<byte_t> buffer(buffer_size);
            hash256_one_by_one hasher;
            // hasher.init();
            while (first != last)
            {
                int size = buffer_size;
                for (int i = 0; i != buffer_size; ++i, ++first)
                {
                    if (first == last)
                    {
                        size = i;
                        break;
                    }
                    buffer[i] = *first;
                }
                hasher.process(buffer.begin(), buffer.begin() + size);
            }
            hasher.finish();
            hasher.get_hash_bytes(first2, last2);
        }
    }

    template <typename InIter, typename OutIter>
    void hash256(InIter first, InIter last, OutIter first2, OutIter last2,
                 int buffer_size = PICOSHA2_BUFFER_SIZE_FOR_INPUT_ITERATOR)
    {
        picosha2::impl::hash256_impl(
            first, last, first2, last2, buffer_size,
            typename std::iterator_traits<InIter>::iterator_category());
    }

    template <typename InIter, typename OutContainer>
    void hash256(InIter first, InIter last, OutContainer &dst)
    {
        hash256(first, last, dst.begin(), dst.end());
    }

    template <typename InContainer, typename OutIter>
    void hash256(const InContainer &src, OutIter first, OutIter last)
    {
        hash256(src.begin(), src.end(), first, last);
    }

    template <typename InContainer, typename OutContainer>
    void hash256(const InContainer &src, OutContainer &dst)
    {
        hash256(src.begin(), src.end(), dst.begin(), dst.end());
    }

    template <typename InIter>
    void hash256_hex_string(InIter first, InIter last, std::string &hex_str)
    {
        byte_t hashed[32];
        hash256(first, last, hashed, hashed + 32);
        std::ostringstream oss;
        output_hex(hashed, hashed + 32, oss);
        hex_str.assign(oss.str());
    }

    template <typename InIter>
    std::string hash256_hex_string(InIter first, InIter last)
    {
        std::string hex_str;
        hash256_hex_string(first, last, hex_str);
        return hex_str;
    }

    inline void hash256_hex_string(const std::string &src, std::string &hex_str)
    {
        hash256_hex_string(src.begin(), src.end(), hex_str);
    }

    template <typename InContainer>
    void hash256_hex_string(const InContainer &src, std::string &hex_str)
    {
        hash256_hex_string(src.begin(), src.end(), hex_str);
    }

    template <typename InContainer>
    std::string hash256_hex_string(const InContainer &src)
    {
        return hash256_hex_string(src.begin(), src.end());
    }

} // namespace picosha2

namespace aes
{

    typedef std::vector<std::vector<int>> MATRIX;
    typedef std::vector<int> VECTOR;
    const int ROUNDS = 10;
    const std::string DELIMITER = "OA";
    const MATRIX SUBBYTES = {
        {99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118},
        {202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192},
        {183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21},
        {4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117},
        {9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132},
        {83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207},
        {208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168},
        {81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210},
        {205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115},
        {96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219},
        {224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121},
        {231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8},
        {186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138},
        {112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158},
        {225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223},
        {140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22}};
    const MATRIX ROUNDCONST = {
        {1, 0, 0, 0},
        {2, 0, 0, 0},
        {4, 0, 0, 0},
        {8, 0, 0, 0},
        {16, 0, 0, 0},
        {32, 0, 0, 0},
        {64, 0, 0, 0},
        {128, 0, 0, 0},
        {27, 0, 0, 0},
        {54, 0, 0, 0},
        {108, 0, 0, 0},
        {216, 0, 0, 0},
        {171, 0, 0, 0},
        {77, 0, 0, 0},
    };
    const MATRIX MIXCOLS = {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}};
    const MATRIX MIXCOLS_INV = {
        {14, 11, 13, 9},
        {9, 14, 11, 13},
        {13, 9, 14, 11},
        {11, 13, 9, 14}};
    const MATRIX EMPTY = {
        {0, 0, 0, 0},
        {0, 0, 0, 0},
        {0, 0, 0, 0},
        {0, 0, 0, 0}};

    // Pad the data to be divisible by 16
    VECTOR pad(VECTOR vec)
    {
        int padding = 16 - (vec.size() % 16);
        if (padding == 16)
        {
            return vec;
        }
        for (int i = 0; i < padding; ++i)
        {
            vec.push_back(vec[i]);
        }
        return vec;
    }

    // Slice a vector into a subvector
    VECTOR slice(VECTOR &v, int m, int n)
    {
        VECTOR vec = {};
        std::copy(v.begin() + m, v.begin() + n + 1, std::back_inserter(vec));
        return vec;
    }

    // Utility function to print a matrix to the console
    void printMatrix(MATRIX mat)
    {
        std::cout << "\n";
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                std::cout << mat[i][j] << " ";
            }
            std::cout << "\n";
        }
    }

    // Utility function to print a vector to the console
    void printVector(VECTOR vec)
    {
        std::cout << "\n";
        for (int i : vec)
            std::cout << i << " ";
    }

    // Create a 4x4 column-wise matrix from a 16x1 array
    MATRIX createMatrix(VECTOR vec)
    {
        MATRIX mat = EMPTY;
        assert(vec.size() == 16);
        for (int i = 0; i < 16; ++i)
        {
            int x = i / 4, y = i % 4;
            mat[y][x] = vec[i]; // Column-wise
        }
        return mat;
    }

    // Replace 10-16 with A-F
    char intToHexChar(int i)
    {
        if (0 <= i && i <= 9)
        {
            return char(i + 48);
        }
        return char(i + 55);
    }

    // Replace A-F with 10-16
    int hexCharToInt(char c)
    {
        int asciiValue = int(c);
        if (65 <= asciiValue && asciiValue <= 71)
        {
            return asciiValue - 55;
        }
        else if (97 <= asciiValue && asciiValue <= 103)
        {
            return asciiValue - 87;
        }
        else
        {
            return asciiValue - 48;
        }
    }

    // Convert an 8 bit decimal integer to a 2-char hexadecimal digit
    std::string hex(int i)
    {
        int bit1 = i / 16, bit2 = i % 16;
        return std::string(1, intToHexChar(bit1)) + std::string(1, intToHexChar(bit2));
    }

    // Convert a 2-char hexadecimal string to an 8-bit decimal integer
    int denary(std::string hexString)
    {
        return (16 * hexCharToInt(hexString[0])) + hexCharToInt(hexString[1]);
    }

    // Returns elements in a specific column of a 4x4 matrix
    VECTOR getColumn(MATRIX mat, int col)
    {
        VECTOR output = {};
        for (int i = 0; i < 4; ++i)
        {
            output.push_back(mat[i][col]);
        }
        return output;
    }

    // Set a column of a 4x4 matrix as a 1x4 vector
    MATRIX setColumn(MATRIX mat, VECTOR vec, int col)
    {
        for (int i = 0; i < 4; ++i)
        {
            mat[i][col] = vec[i];
        }
        return mat;
    }

    // Convert a matrix into a hex digest (hexadecimal string)
    std::string reformat(MATRIX data)
    {
        std::string output = "";
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                output += hex(data[j][i]);
            }
        }
        return output;
    }

    // Convert a string to an integer array
    VECTOR toIntegerArray(std::string str)
    {
        VECTOR output = {};
        for (char c : str)
        {
            output.push_back(int(c));
        }
        return output;
    }

    // Convert an integer array to ASCII characters
    std::string toPlainText(VECTOR vec)
    {
        std::string output = "";
        for (int i : vec)
        {
            output += char(i);
        }
        return output;
    }

    // Convert a 4x4 matrix of integers to ASCII characters
    std::string toPlainText(MATRIX mat)
    {
        std::string output = "";
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                output += char(mat[j][i]);
            }
        }
        return output;
    }

    // XOR gate for each element in two vectors
    VECTOR xorVector(VECTOR vec1, VECTOR vec2)
    {
        VECTOR output = {};
        assert(vec1.size() == vec2.size());
        for (int i = 0; i < vec1.size(); ++i)
        {
            output.push_back(vec1[i] ^ vec2[i]);
        }
        return output;
    }

    // Cumulative XOR function of an array (not reversible)
    int xorSum(VECTOR vec)
    {
        int output = vec[0];
        for (int i = 1; i < vec.size(); ++i)
        {
            output ^= vec[i];
        }
        return output;
    }

    // Read the contents of a binary or text file
    std::string readFile(std::string fileName, bool concatenateLines = true)
    {
        std::ifstream inputFile(fileName, std::ios::binary);
        if (!inputFile.is_open())
        {
            throw std::runtime_error("Failed to open file!");
        }
        std::string contents = "";
        if (concatenateLines)
        {
            std::string line = "";
            while (std::getline(inputFile, line))
            {
                contents += line;
            }
        }
        else
        {
            char ch;
            while (inputFile >> std::noskipws >> ch)
            {
                contents += ch;
            }
        }
        inputFile.close();
        return contents;
    }

    // Writes text or binary strings to a file
    void writeToFile(std::string fileName, std::string contents, int lineLength = 80)
    {
        std::ofstream outputFile(fileName, std::ios::binary);
        if (!outputFile.is_open())
        {
            throw std::runtime_error("Failed to open file!");
        }
        for (int i = 1; i < contents.length() + 1; ++i)
        {
            if (i % lineLength == 0 && lineLength != -1)
            {
                outputFile.put('\n');
            }
            outputFile.put(contents[i - 1]);
        }
        outputFile.close();
    }

    MATRIX generateRoundKey(MATRIX prevKey, int roundNum)
    {
        MATRIX output = EMPTY;

        // Calcluate first column with shift and sub bytes
        VECTOR col = getColumn(prevKey, 3);
        VECTOR firstCol = getColumn(prevKey, 0);
        col.push_back(col[0]);
        col.erase(col.begin());
        for (int i = 0; i < 4; ++i)
        {
            int value = col[i];
            col[i] = SUBBYTES[value / 16][value % 16];
            firstCol[i] = (firstCol[i] ^ col[i] ^ ROUNDCONST[roundNum][i]);
        }

        VECTOR colResultant = firstCol;
        output = setColumn(output, colResultant, 0);
        for (int i = 1; i < 4; ++i)
        {
            VECTOR col = getColumn(prevKey, i);
            colResultant = xorVector(col, colResultant);
            output = setColumn(output, colResultant, i);
        }
        return output;
    }

    std::vector<MATRIX> expandKey(MATRIX key)
    {
        std::vector<MATRIX> roundKeys = {
            key,
        };
        for (int i = 0; i < ROUNDS; ++i)
        {
            MATRIX roundKey = generateRoundKey(roundKeys[i], i);
            roundKeys.push_back(roundKey);
        }
        return roundKeys;
    }

    VECTOR deriveKey(std::string password = "")
    {
        VECTOR output = {};
        if (password != "")
        {
            std::string hexDigest = picosha2::hash256_hex_string(password);
            for (int i = 0; i < hexDigest.length(); i += 4)
            {
                output.push_back(denary(hexDigest.substr(i, 2)) ^ denary(hexDigest.substr(i + 2, 2)));
            }
        }
        return output;
    }

    // Find a value from a lookup table
    int lookup(int i, MATRIX table = SUBBYTES)
    {
        int x = i / 16, y = i % 16;
        return table[x][y];
    }

    // Find the table co-ordinates from a value (inverse for sub bytes round step)
    int inverseLookup(int n, MATRIX table = SUBBYTES)
    {
        for (int i = 0; i < table.size(); ++i)
        {
            for (int j = 0; j < table[i].size(); ++j)
            {
                if (table[i][j] == n)
                {
                    return i * 16 + j;
                }
            }
        }
        return -1;
    }

    // Mixcols transformation function for 2 elements
    int transform(int i, int j)
    {
        switch (j)
        {
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
    MATRIX subBytes(MATRIX data, bool inverse = false)
    {
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                if (!inverse)
                {
                    data[i][j] = lookup(data[i][j]);
                }
                else
                {
                    data[i][j] = inverseLookup(data[i][j]);
                }
            }
        }
        return data;
    }

    // Permutation by performing an element-wise shift for each row by it's index
    MATRIX shiftRows(MATRIX data, bool inverse = false)
    {
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < (inverse ? 4 - i : i); ++j)
            {
                data[i].push_back(data[i][0]);
                data[i].erase(data[i].begin());
            }
        }
        return data;
    }

    // Mixcolumns matrix multiplication function inside a Galois Field
    MATRIX mixColumns(MATRIX data, bool inverse = false)
    {
        MATRIX mat = (inverse ? MIXCOLS_INV : MIXCOLS), output = EMPTY;
        for (int i = 0; i < 4; ++i)
        {
            VECTOR row = mat[i];
            for (int j = 0; j < 4; ++j)
            {
                VECTOR col = getColumn(data, j), products = {};
                for (int n = 0; n < 4; ++n)
                {
                    products.push_back(transform(col[n], row[n]));
                }
                output[i][j] = xorSum(products);
            }
        }
        return output;
    }

    // Add the generated round key to the matrix using column-wise XOR gates
    MATRIX addRoundKey(MATRIX data, MATRIX roundKey)
    {
        for (int i = 0; i < 4; ++i)
        {
            data = setColumn(data, xorVector(getColumn(data, i), getColumn(roundKey, i)), i);
        }
        return data;
    }

    // Perform 1 AES round
    MATRIX round(MATRIX data, MATRIX roundKey, bool doMixCols = true)
    {
        data = subBytes(data);
        data = shiftRows(data);
        if (doMixCols)
        {
            data = mixColumns(data);
        }
        data = addRoundKey(data, roundKey);
        return data;
    }

    // Perform 1 inverse AES round
    MATRIX roundInverse(MATRIX data, MATRIX roundKey, bool doMixCols = true)
    {
        data = addRoundKey(data, roundKey);
        if (doMixCols)
        {
            data = mixColumns(data, true);
        }
        data = shiftRows(data, true);
        data = subBytes(data, true);
        return data;
    }

    // Perform the Rijndael Cipher (AES) on a 128-bit block of data
    MATRIX rijndaelCipher(MATRIX data, std::vector<MATRIX> roundKeys)
    {
        data = addRoundKey(data, roundKeys[0]);
        for (int i = 1; i < ROUNDS + 1; ++i)
        {
            bool doMixCols = (i != ROUNDS);
            data = round(data, roundKeys[i], doMixCols);
        }
        return data;
    }

    // Reconstruct the original data from a 128-bit block of cipher text (reverse Rijndael Cipher)
    MATRIX rijndaelInverse(MATRIX data, std::vector<MATRIX> roundKeys)
    {
        for (int i = 1; i < ROUNDS + 1; ++i)
        {
            bool doMixCols = (i != 1);
            data = roundInverse(data, roundKeys[(ROUNDS - i) + 1], doMixCols);
        }
        data = addRoundKey(data, roundKeys[0]);
        return data;
    }

    // Full encryption function
    std::string encrypt(std::string stringData, std::string password, std::string outputMode = "hex", int rlevel = 0)
    {
        int padding = 16 - (stringData.length() % 16);
        std::string dtype = hex(1), enc = "", output = "";
        // Encrypt password with itself to validate upon decryption
        if (password != "")
        {
            if (!rlevel)
            {
                enc = encrypt(password, password, "hex", 1);
            }
        }
        // Prepend headers / metadata to the output
        output = output + hex(padding) + dtype + enc + (!rlevel ? DELIMITER : "");
        VECTOR data = pad(toIntegerArray(stringData));
        MATRIX key = createMatrix(deriveKey(password));
        std::vector<MATRIX> roundKeys = expandKey(key);
        // Perform a Rijndael cipher on each block of data and convert to hex digest
        for (int i = 0; i < data.size(); i += 16)
        {
            MATRIX block = createMatrix(slice(data, i, i + 15));
            MATRIX cipherBlock = rijndaelCipher(block, roundKeys);
            output += reformat(cipherBlock);
        }
        // Encode to base-64 if necessary
        if (outputMode == "base64")
        {
            return b64::encode(output);
        }
        return output;
    }

    // Entire decryption process
    std::string decrypt(std::string stringData, std::string password = "", std::string key = "", std::string inputMode = "hex", int rlevel = 0)
    {
        if (inputMode == "base64")
        {
            stringData = b64::decode(stringData);
        }
        // Recreate key and round keys
        VECTOR keyVector = {};
        if (password != "")
        {
            keyVector = deriveKey(password);
        }
        else
        {
            keyVector = toIntegerArray(key);
        }
        std::vector<MATRIX> roundKeys = expandKey(createMatrix(keyVector));
        // Split message into headers and body text
        std::string headers = "";
        if (!rlevel)
        {
            for (int i = 0; i < stringData.length(); i += 2)
            {
                if (stringData.substr(i, 2) == DELIMITER)
                {
                    headers = stringData.substr(0, i);
                    stringData = stringData.substr(i + 2, stringData.length() - (i + 2));
                    break;
                }
            }
        }
        else
        {
            headers = stringData;
        }
        // Parse message headers
        int padding = denary(headers.substr(0, 2));
        int dtype = denary(headers.substr(2, 4));
        if (password != "" && headers.length() > 4)
        {
            std::string encryptedPassword = headers.substr(4, headers.length() - 4);
            if (!rlevel)
            {
                std::string decryptedPassword = decrypt(encryptedPassword, password, "", "hex", 1);
                if (decryptedPassword != password)
                {
                    throw std::runtime_error("Invalid password!");
                }
            }
        }
        // Convert hex digest into base-10 integer array
        VECTOR data = {};
        for (int i = 0; i < stringData.length(); i += 2)
        {
            data.push_back(denary(stringData.substr(i, 2)));
        }
        std::string output = "";
        if (rlevel)
        {
            data = slice(data, 2, data.size() - 1);
        }
        // Perform inverse Rijndael cipher on each block of data
        for (int i = 0; i < data.size(); i += 16)
        {
            MATRIX block = createMatrix(slice(data, i, i + 15));
            MATRIX plainTextBlock = rijndaelInverse(block, roundKeys);
            output += toPlainText(plainTextBlock);
        }
        if (padding)
        {
            output = output.substr(0, output.length() - padding);
        }
        return output;
    }

    // Encrypt the contents of a file using a specific password
    void encryptFile(std::string fileName, std::string password, int lineLength = 80)
    {
        std::string contents = readFile(fileName, false);
        std::string enc = encrypt(contents, password);
        writeToFile(fileName, enc, lineLength);
    }

    // Decrypt an encrypted file using a specific password
    void decryptFile(std::string fileName, std::string password)
    {
        std::string enc = readFile(fileName, true);
        std::string decrypted = decrypt(enc, password);
        writeToFile(fileName, decrypted, -1);
    }

    // External interface
    // Use char pointers instead of strings to allow type conversion through builtin Python ctypes module
    extern "C"
    {

        char *encrypt(char *stringData, char *password, char *outputMode)
        {
            std::string enc = encrypt(std::string(stringData), std::string(password), std::string(outputMode), 0);
            std::cout << (char *)enc.c_str() << std::endl;
            return (char *)enc.c_str();
        }

        char *decrypt(char *stringData, char *password, char *inputMode)
        {
            std::string output = decrypt(std::string(stringData), std::string(password), NULL, std::string(inputMode), 0);
            return (char *)output.c_str();
        }

        void encryptFile(char *fileName, char *password, int lineLength)
        {
            return encryptFile(std::string(fileName), std::string(password), lineLength);
        }

        void decryptFile(char *fileName, char *password)
        {
            return decryptFile(std::string(fileName), std::string(password));
        }

    } // extern "C"

} // namespace aes
