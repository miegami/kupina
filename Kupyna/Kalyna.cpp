#include "Kalyna.h"
#include <iomanip>

Kalyna::Kalyna(unsigned int block_size, unsigned int key_size, unsigned __int64* key)
{
    this->block_size = block_size;
    this->block_size_words = block_size / 64;
    this->block_size_bytes = block_size / 8;
    this->key_size = key_size;
    switch (key_size) {
    case 128:
        rounds = 10;
        break;
    case 256:
        rounds = 14;
        break;
    case 512:
        rounds = 18;
        break;
    }
    rkeys = new unsigned __int64[block_size_words * (rounds + 1)];

    s_key_inv((unsigned char*)s, (unsigned char*)s_inv);
    form_v_index(V_init_string, (unsigned char*)V_index);
    form_v_index(V_inv_init_string, (unsigned char*)V_inv_index);

    unsigned char v_init[] = { 1, 4, 5, 6, 7, 8 };
    m_col_precalc(v_init, 6, (unsigned char*)m_col_precalculation_matrix);

    unsigned __int8 v_init_inv[8] = { 0x2F, 0x49, 0x76, 0x95, 0xA8, 0xAD, 0xCA, 0xD7 };
    m_col_precalc(v_init_inv, 8, (unsigned char*)m_col_inv_precalculation_matrix);

    expand_key(key);
}

Kalyna::~Kalyna()
{
    delete[] rkeys;
}

void Kalyna::s_key_inv(unsigned char* key, unsigned char* inv_key)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 256; j++)
            inv_key[i * 256 + key[i * 256 + j]] = j;
}

void Kalyna::s_box(unsigned char* message, unsigned char* key)
{
    for (int i = 0; i < block_size_bytes; i++)
        message[i] = key[(i % 4) * 256 + message[i]];
}

void Kalyna::xor_rkey(unsigned __int64* message, unsigned __int64* key)
{
    for (int i = 0; i < block_size_words; i++)
        message[i] = message[i] ^ key[i];
}

void Kalyna::add_rkey(unsigned __int64* message, unsigned __int64* key)
{
    for (int i = 0; i < block_size_words; i++) {
        message[i] = message[i] + key[i];
    }
}

void Kalyna::sub_rkey(unsigned __int64* message, unsigned __int64* key)
{
    for (int i = 0; i < block_size_words; i++) {
        message[i] = message[i] - key[i];
    }
}

void Kalyna::s_row(unsigned char* message)
{
    const int rows = 8;
    int shift = -1;
    int columns = block_size_words;
    unsigned __int8* buffer = new unsigned __int8[rows * columns];
    for (int i = 0; i < rows; i++) {
        if (i % (rows / columns) == 0)
            shift++;
        for (int j = 0; j < columns; j++) {
            buffer[i + ((j + shift) % columns) * rows] = message[i + j * rows];
        }
    }
    for (int i = 0; i < rows * columns; i++)
        message[i] = buffer[i];
    delete[] buffer;
}

void Kalyna::inv_s_row(unsigned char* message)
{
    const int rows = 8;
    int shift = -1;
    int columns = block_size_words;
    unsigned __int8* buffer1 = new unsigned __int8[rows * columns];
    unsigned __int8* buffer2 = new unsigned __int8[rows * columns];
    for (int i = 0; i < rows * columns; i++)
        buffer1[i] = message[i / 8 * 8 + 7 - i % 8];
    for (int i = 0; i < rows; i++) {
        if (i % (rows / columns) == 0)
            shift++;
        for (int j = 0; j < columns; j++) {
            buffer2[i + j * rows] = buffer1[i + ((j + shift) % columns) * rows];
        }
    }
    for (int i = 0; i < rows * columns; i++)
        message[i] = buffer2[i / 8 * 8 + 7 - i % 8];
    delete[] buffer1;
    delete[] buffer2;
}

unsigned char Kalyna::multiply(unsigned char _a, unsigned char _b)
{
    unsigned int mod = 0x011d; /* x^8 + x^4 + x^3 + x^2 + 1 */
    unsigned int a = _a;
    unsigned int b = _b;
    unsigned char res = 0;
    while (a) {
        if (a & 1)
            res ^= b;
        b <<= 1;
        if (b > 0xff)
            b ^= mod;
        a >>= 1;
    }
    return res;
}

void Kalyna::m_col_precalc(unsigned char* v_init, int length, unsigned char* precalc_matrix)
{
    for (int i = 0; i < length; i++) {
        if (v_init[i] == 1)
            for (int j = 0; j < 256; j++)
                precalc_matrix[i * 256 + j] = j;
        else {
            precalc_matrix[i * 256] = 0;
            for (int j = 1; j < 256; j++) {
                precalc_matrix[i * 256 + j] = multiply(v_init[i], j);
            }
        }
    }
}

void Kalyna::m_col(unsigned char* message, unsigned char* s, unsigned char* v_indexes)
{
    unsigned char* result = new unsigned __int8[block_size_bytes];
    for (int i = 0; i < block_size_words; i++) {
        for (int j = 0; j < 8; j++) {
            result[i * 8 + j] = 0;
            for (int k = 0; k < 8; k++) {
                result[i * 8 + j] ^= s[v_indexes[j * 8 + k] * 256 + message[i * 8 + k]];
            }
        }
    }
    memcpy(message, result, block_size_bytes);
    delete[] result;
}

void Kalyna::form_v_index(unsigned char* init_string, unsigned char* result)
{
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            result[i * 8 + (j + i) % 8] = init_string[j];
}

void Kalyna::output(unsigned __int64* state)
{
    unsigned char* a = (unsigned char*)state;
    std::cout << std::hex;
    for (int i = 0; i < block_size_bytes; i++) {
        if (i % 8 == 0)
            std::cout << "  ";
        std::cout << std::setw(2) << std::setfill('0') << (int)a[i];
    }
    std::cout << "\n";
}

void Kalyna::encipher_round(unsigned __int64* state)
{
    unsigned __int64 buffer;
    s_box((unsigned char*)state, (unsigned char*)s);
    s_row((unsigned char*)state);
    m_col((unsigned char*)state, (unsigned char*)m_col_precalculation_matrix, (unsigned char*)V_index);
}

void Kalyna::shift_left(unsigned __int64* state)
{
    for (int i = 0; i < block_size_words; ++i) {
        state[i] <<= 1;
    }
}

void Kalyna::rotate(unsigned __int64* state)
{
    unsigned __int64 temp = state[0];
    for (int i = 1; i < key_size / 64; ++i) {
        state[i - 1] = state[i];
    }
    state[key_size / 64 - 1] = temp;
}

void Kalyna::rotate_left(unsigned __int64* state)
{
    unsigned __int8* state_buf = (unsigned __int8*)state;
    unsigned __int8* buffer1 = new unsigned __int8[block_size_bytes];
    unsigned __int8* buffer2 = new unsigned __int8[block_size_bytes];
    unsigned __int64 shift = 2 * block_size_words + 3;
    for (int i = 0; i < block_size_bytes; i++)
        buffer1[i] = state_buf[(i + shift) % block_size_bytes];
    for (int i = 0; i < block_size_bytes; i++)
        state_buf[i] = buffer1[i];

    delete[] buffer1;
    delete[] buffer2;
}

void Kalyna::encipher(unsigned __int64* message)
{
    add_rkey(message, rkeys);
    for (int i = 1; i < rounds; i++) {
        encipher_round(message);
        xor_rkey(message, rkeys + i * block_size_words);
    }
    encipher_round(message);
    add_rkey(message, rkeys + rounds * block_size_words);
}

using namespace std;

void Kalyna::expand_key(unsigned __int64* key)
{
    std::cout << std::hex << std::setw(2) << std::setfill('0');

    unsigned __int64* Ka = new unsigned __int64[block_size_words];
    unsigned __int64* Kw = new unsigned __int64[block_size_words];
    unsigned __int64* state = new unsigned __int64[block_size_words];

    state[0] = (block_size + key_size) / 64 + 1;
    for (int i = 1; i < block_size_words; i++)
        state[i] = 0;
    memcpy(Ka, key, block_size / 8);
    if (key_size == block_size)
        memcpy(Kw, key, block_size / 8);
    else
        memcpy(Kw, key + block_size_words, block_size / 8);

    add_rkey(state, Ka);
    encipher_round(state);

    xor_rkey(state, Kw);
    encipher_round(state);

    add_rkey(state, Ka);
    encipher_round(state);

    unsigned __int64* round_state = new unsigned __int64[block_size_words];
    unsigned __int64* constant_for_keys = new unsigned __int64[block_size_words];

    for (int i = 0; i < block_size_words; i++) {
        constant_for_keys[i] = 0x0001000100010001;
    }

    unsigned __int64* shifted_key = new unsigned __int64[block_size_words];
    for (int i = 0; i <= rounds; i += 2) {
        if (block_size == key_size) {
            memcpy(shifted_key, key, block_size_bytes);
        } else {
            if (i % 4 == 0)
                memcpy(shifted_key, key, block_size_bytes);
            else
                memcpy(shifted_key, key + block_size_words, block_size_bytes);
        }

        memcpy(round_state, state, block_size_bytes);
        add_rkey(round_state, constant_for_keys);
        memcpy(rkeys + i * block_size_words, shifted_key, block_size_bytes);
        add_rkey(rkeys + i * block_size_words, round_state);
        encipher_round(rkeys + i * block_size_words);

        xor_rkey(rkeys + i * block_size_words, round_state);
        encipher_round(rkeys + i * block_size_words);

        add_rkey(rkeys + i * block_size_words, round_state);
        shift_left(constant_for_keys);

        if (block_size == key_size || i % 4 == 2)
            rotate(key);
    }

    for (int i = 1; i < rounds; i += 2) {
        memcpy(rkeys + i * block_size_words, rkeys + ((i - 1) * block_size_words), block_size_bytes);
        rotate_left(rkeys + i * block_size_words);

        std::cout << std::dec << i - 1;
        output(rkeys + ((i - 1) * block_size_words));
        std::cout << std::dec << i;
        output(rkeys + i * block_size_words);
    }
    std::cout << std::dec << rounds;
    output(rkeys + rounds * block_size_words);

    delete[] Ka;
    delete[] Kw;
    delete[] state;
    delete[] round_state;
    delete[] constant_for_keys;
    delete[] shifted_key;
}
