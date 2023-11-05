#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

using namespace std;

// Helper functions: right rotate function
uint32_t rightRotate(uint32_t value, int n)
{
    return ((value >> n) | (value << (32 - n))) & 0xFFFFFFFF;
}
// Choose function
uint32_t sha256Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}
// Majority function
uint32_t sha256Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
// Sigma_0 function
uint32_t sha256Sigma0(uint32_t x)
{
    return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
}
// Sigma_1 function
uint32_t sha256Sigma1(uint32_t x)
{
    return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
}
// Gamma_0 function
uint32_t sha256Gamma0(uint32_t x)
{
    return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >> 3);
}
// Gamma_1 function
uint32_t sha256Gamma1(uint32_t x)
{
    return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >> 10);
}

// SHA-256 function to compute the hash
string sha256(const string &message)
{
    // Initialize constants h0 through h7
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Constants for each round
    const uint32_t K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // Pre-processing: Padding the message
    vector<uint8_t> paddedMessage(message.begin(), message.end());
    paddedMessage.push_back(0x80); // Append a single '1' bit
    while (paddedMessage.size() % 64 != 56)
    {
        paddedMessage.push_back(0x00); // Append zeros
    }

    // Append the original message length as a 64-bit big-endian integer
    uint64_t messageLength = 8 * message.size();
    for (int i = 0; i < 8; ++i)
    {
        paddedMessage.push_back((messageLength >> (56 - i * 8)) & 0xFF);
    }

    // Process the message in 512-bit blocks
    for (size_t i = 0; i < paddedMessage.size(); i += 64)
    {
        vector<uint32_t> words(64);

        // Break the block into 32-bit words (big-endian)
        for (size_t j = 0; j < 16; ++j)
        {
            words[j] = (paddedMessage[i + j * 4] << 24) | (paddedMessage[i + j * 4 + 1] << 16) |
                       (paddedMessage[i + j * 4 + 2] << 8) | (paddedMessage[i + j * 4 + 3]);
        }

        // Extend the 16 32-bit words into 64 32-bit words
        for (size_t j = 16; j < 64; ++j)
        {
            uint32_t s0 = rightRotate(words[j - 15], 7) ^ rightRotate(words[j - 15], 18) ^ (words[j - 15] >> 3);
            uint32_t s1 = rightRotate(words[j - 2], 17) ^ rightRotate(words[j - 2], 19) ^ (words[j - 2] >> 10);
            words[j] = words[j - 16] + s0 + words[j - 7] + s1;
        }

        // Initialize hash values for this chunk
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        // Main loop
        for (size_t j = 0; j < 64; ++j)
        {
            uint32_t S1 = sha256Sigma1(e);
            uint32_t ch = sha256Ch(e, f, g);
            uint32_t temp1 = h + S1 + ch + K[j] + words[j];
            uint32_t S0 = sha256Sigma0(a);
            uint32_t maj = sha256Maj(a, b, c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update hash values for this chunk
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Concatenate the hash values (big-endian) to get the final hash
    uint8_t hashBytes[32];
    for (int i = 0; i < 4; ++i)
    {
        hashBytes[i] = (h0 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 4] = (h1 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 8] = (h2 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 12] = (h3 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 16] = (h4 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 20] = (h5 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 24] = (h6 >> (24 - i * 8)) & 0xFF;
        hashBytes[i + 28] = (h7 >> (24 - i * 8)) & 0xFF;
    }

    // Convert the hash bytes to a hexadecimal string
    string result;
    for (int i = 0; i < 32; ++i)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hashBytes[i]);
        result += hex;
    }

    return result;
}

string trim(const string& str) {
    // Find the first non-whitespace character
    size_t first = str.find_first_not_of(" \t\n\r");

    // If the string is all whitespace, return an empty string
    if (first == string::npos) {
        return "";
    }

    // Find the last non-whitespace character
    size_t last = str.find_last_not_of(" \t\n\r");

    // Return the substring without leading and trailing whitespace
    return str.substr(first, (last - first + 1));
}

int main()
{
    // Takes input from the user and prints its SHA-256 hash in hexadecimal
    string message;
    cout << "Enter the string to be hashed: ";
    cin >> message;
    string new_message = trim(message);
    string hashed = sha256(new_message);
    cout << "SHA-256 Hash: " << hashed << endl;
    cout << "Length: " << hashed.length() << endl;
    return 0;
}
