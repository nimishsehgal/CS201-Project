#include <iostream>
#include <cstdint>
#include <cstring>

// BLAKE2_INLINE macro definition
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if defined(_MSC_VER)
    #define BLAKE2_INLINE __inline
  #elif defined(__GNUC__)
    #define BLAKE2_INLINE __inline__
  #else
    #define BLAKE2_INLINE
  #endif
#else
  #define BLAKE2_INLINE inline
#endif

// Function to load a 32-bit value from memory
static BLAKE2_INLINE uint32_t load32(const void* src)
{
  // Check if the system is little-endian
  // If it's little-endian, we can directly load the value using memcpy
  #if defined(NATIVE_LITTLE_ENDIAN)
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
  #else
    // For big-endian systems, manually construct the 32-bit value from bytes
    const uint8_t* p = (const uint8_t*)src;
    return ((uint32_t)(p[0]) << 0) |
           ((uint32_t)(p[1]) << 8) |
           ((uint32_t)(p[2]) << 16) |
           ((uint32_t)(p[3]) << 24);
  #endif
}

// Function to load a 64-bit value from memory
static BLAKE2_INLINE uint64_t load64(const void* src)
{
  // Check if the system is little-endian
  // If it's little-endian, we can directly load the value using memcpy
  #if defined(NATIVE_LITTLE_ENDIAN)
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
  #else
    // For big-endian systems, manually construct the 64-bit value from bytes
    const uint8_t* p = (const uint8_t*)src;
    return ((uint64_t)(p[0]) << 0) |
           ((uint64_t)(p[1]) << 8) |
           ((uint64_t)(p[2]) << 16) |
           ((uint64_t)(p[3]) << 24) |
           ((uint64_t)(p[4]) << 32) |
           ((uint64_t)(p[5]) << 40) |
           ((uint64_t)(p[6]) << 48) |
           ((uint64_t)(p[7]) << 56);
  #endif
}


// Function to load a 16-bit value from memory
static BLAKE2_INLINE uint16_t load16(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  // If the system is little-endian, we can directly load the 16-bit value using memcpy
  uint16_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  // For big-endian systems, manually construct the 16-bit value from bytes
  const uint8_t* p = (const uint8_t*)src;
  return (uint16_t)(((uint32_t)(p[0]) << 0) |
                    ((uint32_t)(p[1]) << 8));
#endif
}

// Function to store a 16-bit value to memory
static BLAKE2_INLINE void store16(void* dst, uint16_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  // If the system is little-endian, we can directly store the 16-bit value using memcpy
  memcpy(dst, &w, sizeof w);
#else
  // For big-endian systems, manually store the 16-bit value as two bytes
  uint8_t* p = (uint8_t*)dst;
  *p++ = (uint8_t)w;     // Store the LSB
  w >>= 8;               // Shift to the next byte
  *p++ = (uint8_t)w;     // Store the MSB
#endif
}

// Function to store a 32-bit value to memory
static BLAKE2_INLINE void store32(void* dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  // If the system is little-endian, we can directly store the 32-bit value using memcpy
  memcpy(dst, &w, sizeof w);
#else
  // For big-endian systems, manually store the 32-bit value as four bytes
  uint8_t* p = (uint8_t*)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

// Function to store a 64-bit value to memory
static BLAKE2_INLINE void store64(void* dst, uint64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  // If the system is little-endian, we can directly store the 64-bit value using memcpy
  memcpy(dst, &w, sizeof w);
#else
  // For big-endian systems, manually store the 64-bit value as eight bytes
  uint8_t* p = (uint8_t*)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
  p[6] = (uint8_t)(w >> 48);
  p[7] = (uint8_t)(w >> 56);
#endif
}

// Function to load a 48-bit value from memory
static BLAKE2_INLINE uint64_t load48(const void* src)
{
  const uint8_t* p = (const uint8_t*)src;
  return ((uint64_t)(p[0]) << 0) |
         ((uint64_t)(p[1]) << 8) |
         ((uint64_t)(p[2]) << 16) |
         ((uint64_t)(p[3]) << 24) |
         ((uint64_t)(p[4]) << 32) |
         ((uint64_t)(p[5]) << 40);
}

// Function to store a 48-bit value to memory
static BLAKE2_INLINE void store48(void* dst, uint64_t w)
{
  uint8_t* p = (uint8_t*)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
}

// Function to perform a right rotation on a 32-bit value
static BLAKE2_INLINE uint32_t rotr32(const uint32_t w, const unsigned c)
{
  return (w >> c) | (w << (32 - c));
}

// Function to perform a right rotation on a 64-bit value
static BLAKE2_INLINE uint64_t rotr64(const uint64_t w, const unsigned c)
{
  return (w >> c) | (w << (64 - c));
}

// Function to securely zero memory to prevent compiler optimization
static BLAKE2_INLINE void secure_zero_memory(void* v, size_t n)
{
  // Use a volatile pointer to prevent the compiler from optimizing out the memset
  static void* (*const volatile memset_v)(void*, int, size_t) = &memset;
  memset_v(v, 0, n);
}


// Define the BLAKE2B state struct
typedef struct blake2b_state
{
  uint64_t h[8]; // Chained state
  uint64_t t[2]; // Total number of bytes
  uint64_t f[2]; // Finalization flag
  uint8_t buf[128]; // Buffer for the input data
  size_t buflen; // Current buffer length in bytes
  size_t outlen; // Desired output length in bytes
  uint8_t last_node; // 1 if last node, 0 otherwise
} blake2b_state;


// BLAKE2B constants - These are the initial values used to initialize the BLAKE2B state
static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL,  // Initial value for h[0]
  0xbb67ae8584caa73bULL,  // Initial value for h[1]
  0x3c6ef372fe94f82bULL,  // Initial value for h[2]
  0xa54ff53a5f1d36f1ULL,  // Initial value for h[3]
  0x510e527fade682d1ULL,  // Initial value for h[4]
  0x9b05688c2b3e6c1fULL,  // Initial value for h[5]
  0x1f83d9abfb41bd6bULL,  // Initial value for h[6]
  0x5be0cd19137e2179ULL   // Initial value for h[7]
};


// BLAKE2B sigma constants:
// These constants are an integral part of the BLAKE2B hashing algorithm and are used in its permutation functions.
// The BLAKE2B algorithm processes data in blocks, and these constants define the specific operations to be applied within each block.
// The constants are organized as an array of 12 sets of 16 values. Each set is used for a different round of mixing in the algorithm.
static const uint8_t blake2b_sigma[12][16] =
{
  { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11, 8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13, 4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12, 1, 3, 9,  5, 0, 15, 4,  8, 6,  2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};


// Compression function G: This function processes a block of data in the BLAKE2B algorithm

static void blake2b_compress(blake2b_state* S, const uint8_t* block)
{
  // Declare variables to hold message words and working variables
  uint64_t m[16]; // Message schedule
  uint64_t v[16]; // Working variables
  size_t i;

  // Initialize the message schedule by loading 16 64-bit words from the block of data
  for (i = 0; i < 16; i++)
  {
    m[i] = load64(block + i * 8); // Load a 64-bit word from the block
  }

  // Initialize the working variables 'v' with the current state 'S'
  for (i = 0; i < 8; i++)
  {
    v[i] = S->h[i]; // Copy hash state into 'v'
  }

  // Initialize the remaining working variables with constants
  for (i = 8; i < 12; i++)
  {
    v[i] = blake2b_IV[i - 8]; // Copy constants into 'v'
  }

  // XOR the working variables with various components of the state
  v[12] = S->t[0] ^ blake2b_IV[4]; // Mixing with state components
  v[13] = S->t[1] ^ blake2b_IV[5];
  v[14] = S->f[0] ^ blake2b_IV[6];
  v[15] = S->f[1] ^ blake2b_IV[7];

// Round function G
  for (i = 0; i < 12; i++)
{
    // Column step
    
    v[0] = v[0] + v[4] + m[blake2b_sigma[i][0]]; // Add m value to v[0] and v[4], and store it in v[0]
    v[12] = rotr64(v[12] ^ v[0], 32); // Perform a 32-bit right rotation on v[12] XORed with v[0] and store the result in v[12]
    v[8] = v[8] + v[12]; // Add v[12] to v[8] and store it in v[8]
    v[4] = rotr64(v[4] ^ v[8], 24); // Perform a 24-bit right rotation on v[4] XORed with v[8] and store the result in v[4]
    v[0] = v[0] + v[4] + m[blake2b_sigma[i][1]]; // Add m value to v[0] and v[4], and store it in v[0]
    v[12] = rotr64(v[12] ^ v[0], 16); // Perform a 16-bit right rotation on v[12] XORed with v[0] and store the result in v[12]
    v[8] = v[8] + v[12]; // Add v[12] to v[8] and store it in v[8]
    v[4] = rotr64(v[4] ^ v[8], 63); // Perform a 63-bit right rotation on v[4] XORed with v[8] and store the result in v[4]

    // Diagonal step
    
    v[1] = v[1] + v[5] + m[blake2b_sigma[i][2]]; // Add m value to v[1] and v[5], and store it in v[1]
    v[13] = rotr64(v[13] ^ v[1], 32); // Perform a 32-bit right rotation on v[13] XORed with v[1] and store the result in v[13]
    v[9] = v[9] + v[13]; // Add v[13] to v[9] and store it in v[9]
    v[5] = rotr64(v[5] ^ v[9], 24); // Perform a 24-bit right rotation on v[5] XORed with v[9] and store the result in v[5]
    v[1] = v[1] + v[5] + m[blake2b_sigma[i][3]]; // Add m value to v[1] and v[5], and store it in v[1]
    v[13] = rotr64(v[13] ^ v[1], 16); // Perform a 16-bit right rotation on v[13] XORed with v[1] and store the result in v[13]
    v[9] = v[9] + v[13]; // Add v[13] to v[9] and store it in v[9]
    v[5] = rotr64(v[5] ^ v[9], 63); // Perform a 63-bit right rotation on v[5] XORed with v[9] and store the result in v[5]

    // Continue similar operations for v[2], v[6], v[3], v[7], v[0], v[5], v[1], v[6], v[2], v[7], v[3], v[4]

    v[2] = v[2] + v[6] + m[blake2b_sigma[i][4]];
    v[14] = rotr64(v[14] ^ v[2], 32);
    v[10] = v[10] + v[14];
    v[6] = rotr64(v[6] ^ v[10], 24);
    v[2] = v[2] + v[6] + m[blake2b_sigma[i][5]];
    v[14] = rotr64(v[14] ^ v[2], 16);
    v[10] = v[10] + v[14];
    v[6] = rotr64(v[6] ^ v[10], 63);

    v[3] = v[3] + v[7] + m[blake2b_sigma[i][6]];
    v[15] = rotr64(v[15] ^ v[3], 32);
    v[11] = v[11] + v[15];
    v[7] = rotr64(v[7] ^ v[11], 24);
    v[3] = v[3] + v[7] + m[blake2b_sigma[i][7]];
    v[15] = rotr64(v[15] ^ v[3], 16);
    v[11] = v[11] + v[15];
    v[7] = rotr64(v[7] ^ v[11], 63);

    v[0] = v[0] + v[5] + m[blake2b_sigma[i][8]];
    v[15] = rotr64(v[15] ^ v[0], 32);
    v[10] = v[10] + v[15];
    v[5] = rotr64(v[5] ^ v[10], 24);
    v[0] = v[0] + v[5] + m[blake2b_sigma[i][9]];
    v[15] = rotr64(v[15] ^ v[0], 16);
    v[10] = v[10] + v[15];
    v[5] = rotr64(v[5] ^ v[10], 63);

    v[1] = v[1] + v[6] + m[blake2b_sigma[i][10]];
    v[12] = rotr64(v[12] ^ v[1], 32);
    v[11] = v[11] + v[12];
    v[6] = rotr64(v[6] ^ v[11], 24);
    v[1] = v[1] + v[6] + m[blake2b_sigma[i][11]];
    v[12] = rotr64(v[12] ^ v[1], 16);
    v[11] = v[11] + v[12];
    v[6] = rotr64(v[6] ^ v[11], 63);

    v[2] = v[2] + v[7] + m[blake2b_sigma[i][12]];
    v[13] = rotr64(v[13] ^ v[2], 32);
    v[9] = v[9] + v[13];
    v[7] = rotr64(v[7] ^ v[9], 24);
    v[2] = v[2] + v[7] + m[blake2b_sigma[i][13]];
    v[13] = rotr64(v[13] ^ v[2], 16);
    v[9] = v[9] + v[13];
    v[7] = rotr64(v[7] ^ v[9], 63);

    v[3] = v[3] + v[4] + m[blake2b_sigma[i][14]];
    v[15] = rotr64(v[15] ^ v[3], 32);
    v[8] = v[8] + v[15];
    v[4] = rotr64(v[4] ^ v[8], 24);
    v[3] = v[3] + v[4] + m[blake2b_sigma[i][15]];
    v[15] = rotr64(v[15] ^ v[3], 16);
    v[8] = v[8] + v[15];
    v[4] = rotr64(v[4] ^ v[8], 63);
 
 }


  // Finalize the state 'S' by XORing the working variables 'v' with the state components
  for (i = 0; i < 8; i++)
  {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8]; // Update the state with the final 'v' values
  }
}

// Initialize the BLAKE2B state
void blake2b_init(blake2b_state* S, size_t outlen)
{
  size_t i;

  // Ensure outlen is within bounds (0 to 64 bytes)
  if (outlen == 0 || outlen > 64)
  {
    outlen = 64; // Default to 64 bytes if outlen is invalid
  }

  // Initialize state variables with initial values (IV)
  for (i = 0; i < 8; i++)
  {
    S->h[i] = blake2b_IV[i];
  }

  // Set the output length and buffer length to 0
  S->outlen = outlen;
  S->buflen = 0;

  // Initialize last_node flag to 0
  S->last_node = 0;

  // Initialize t and f variables to 0
  for (i = 0; i < 2; i++)
  {
    S->t[i] = 0;
    S->f[i] = 0;
  }

  // Clear the buffer memory
  secure_zero_memory(S->buf, sizeof(S->buf));
}

// Update the BLAKE2B state with input data
void blake2b_update(blake2b_state* S, const uint8_t* in, size_t inlen)
{
  size_t i;

  for (i = 0; i < inlen; i++)
  {
    if (S->buflen == 128)
    {
      // Update t and invoke the compression function when the buffer is full
      S->t[0] += 128;
      if (S->t[0] < 128)
      {
        S->t[1]++;
      }
      blake2b_compress(S, S->buf);
      S->buflen = 0;
    }
    S->buf[S->buflen++] = in[i]; // Copy input data into the buffer
  }
}

// Finalize the BLAKE2B hash and store the result in out
void blake2b_final(blake2b_state* S, uint8_t* out)
{
  size_t i;

  // Update t with the remaining buflen
  S->t[0] += S->buflen;
  if (S->t[0] < S->buflen)
  {
    S->t[1]++;
  }

  // Pad the buffer with zeros to reach the block size
  while (S->buflen < 128)
  {
    S->buf[S->buflen++] = 0;
  }

  // Set the finalization flags
  S->f[0] = 0xFFFFFFFFFFFFFFFFULL;

  if (S->last_node)
  {
    S->f[1] = 0xFFFFFFFFFFFFFFFFULL;
  }

  // Perform the final compression step
  blake2b_compress(S, S->buf);

  // Extract the hash result from the state
  for (i = 0; i < S->outlen; i++)
  {
    out[i] = (uint8_t)(S->h[i >> 3] >> (8 * (i & 7)));
  }

  // Clear sensitive data in the state structure
  secure_zero_memory(S, sizeof(blake2b_state));
}

int main()
{
  blake2b_state S;   // Initialize BLAKE2B state
  uint8_t out[64];   // Output buffer for the hash
  std::string input;  // Input string

  std::cout << "Enter a string to hash: ";
  std::cin >> input; // Prompt the user to input a string

  // Initialize the BLAKE2B state with the desired output length (64 bytes)
  blake2b_init(&S, sizeof(out));

  // Update the state with the input data (convert string to bytes)
  blake2b_update(&S, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());

  // Finalize the hash
  blake2b_final(&S, out);

  std::cout << "blake2b hash value:" << std::endl;

  // Print the hash result in hexadecimal format
  for (size_t i = 0; i < sizeof(out); i++)
  {
    std::cout << std::hex << static_cast<int>(out[i]);
  }
  std::cout << std::dec << std::endl; // Reset the output format to decimal

  return 0; // Return 0 to indicate successful program execution
}
