#include<bits/stdc++.h>
using namespace std;

// SHA-3-256 constants
const int ROWS = 5;
const int COLUMNS = 5;
const int RATE = 1088; // Bits

const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// Bitwise rotation functions
template <typename T>
T rotateLeft(T value, size_t count) {
    return (value << count) | (value >> (sizeof(T) * 8 - count));
}

class SHA3 {
public:
    SHA3();
    void update(const std::vector<uint8_t>& data);
    std::vector<uint8_t> final();

private:
    std::array<std::array<uint64_t, 5>, 5> state;
    std::vector<uint8_t> buffer;
    uint64_t bitsProcessed;
    int round;

    void keccakF();
    void theta();
    void absorb(const std::vector<uint8_t>& data, int rateInBytes);
    void rho();
    void pi();
    void chi();
    void iota();
    void pad();
};

SHA3::SHA3() : state{}, buffer(200, 0), bitsProcessed(0), round(0) {}

void SHA3::update(const std::vector<uint8_t>& data) {
    int rateInBytes= RATE / 8;
    absorb(data, rateInBytes);
    keccakF();
}

void SHA3::keccakF() {
    // Implement the Keccak-f permutation
    theta();
    rho();
    pi();
    chi();
    iota();
}

void SHA3::theta() {
    //Perform the theta transformation
    std::array<uint64_t, 5> C, D;

    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
    }

    for (int x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotateLeft(C[(x + 1) % 5], 1);
    }

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[x][y] ^= D[x];
        }
    }
}

void SHA3::rho() {
    // Perform the Rho transformation
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            int shift = (y + 2 * x) % 64;
            state[x][y] = (state[x][y] << shift) | (state[x][y] >> (64 - shift));
        }
    }
}

void SHA3::pi() {
    // Perform the Pi transformation
    std::array<std::array<uint64_t, 5>, 5> tempState;

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            tempState[y][2 * x + 3 * y] = state[x][y];
        }
    }

    state = tempState;
}

void SHA3::chi() {
    // Perform the Chi transformation
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            uint64_t notX = ~state[x][y];
            state[x][y] = state[x][y] ^ ((state[(x + 1) % 5][y] & notX) ^ (state[(x + 2) % 5][y] & state[(x + 1) % 5][y]));
        }
    }
}

void SHA3::iota() {
    // Perform the Iota transformation
    uint64_t RCValue = RC[round];
    state[0][0] ^= RCValue;
    round++;
}

void SHA3::absorb(const std::vector<uint8_t>& data, int rateInBytes) {
    // Absorb the input data into the state matrix
    int dataPos = 0;

    while (dataPos < data.size()) {
        int bytesToAbsorb = std::min(rateInBytes, static_cast<int>(data.size()) - dataPos);

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                if (dataPos < data.size()) {
                    state[x][y] ^= static_cast<uint64_t>(data[dataPos]) << ((8 * (dataPos % rateInBytes)));
                    dataPos++;
                }
            }
        }

        if (dataPos % rateInBytes == 0) {
            keccakF();
            // Clear the state for the next block
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    state[x][y] = 0;
                }
            }
        }
    }
}

void SHA3::pad() {
    // Calculate the number of bytes required to pad the message
    int rateInBytes = RATE / 8;
    int blockSize = rateInBytes - (bitsProcessed / 8 % rateInBytes);
    
    // Append the appropriate padding
    uint8_t paddingValue;
    
    if (blockSize == 1) {
        paddingValue = 0x86;  // Special padding for a single byte
    } else {
        paddingValue = 0x06;
    }

    buffer[bitsProcessed / 8] = paddingValue;
    
    // If blockSize is greater than 1, apply padding until the end of the block
    for (int i = bitsProcessed / 8 + 1; i < bitsProcessed / 8 + blockSize - 1; i++) {
        buffer[i] = 0x00;
    }

    // Mark the end of the padding
    buffer[bitsProcessed / 8 + blockSize - 1] = 0x80;

    // Update the state with the padded message
    absorb(buffer, rateInBytes);
}

std::vector<uint8_t> SHA3::final() {
    // Perform padding and finalization
    pad();
    keccakF();

    // Extract the digest from the state matrix
    std::vector<uint8_t> digest;

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < 8; i++) {
                digest.push_back(static_cast<uint8_t>((state[x][y] >> (8 * i)) & 0xFF));
            }
        }
    }

    return digest;
}
//Beginning of the main function
int main() {
    SHA3 sha3;
    string s;
    cin>>s;
    vector<uint8_t> message;
    for(int i=0; i<s.size(); i++)
    {
        message.push_back(s[i]);
    }
    sha3.update(message);
    std::vector<uint8_t> hash = sha3.final();
    std::cout << "SHA-3-256 Hash: ";
    for (uint8_t byte : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
    return 0;
}