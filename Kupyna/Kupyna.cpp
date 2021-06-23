#include "Kupyna.h"
#include <iomanip>
#include <iostream>

Kupyna::Kupyna(unsigned int block_size)
{
    this->block_size = block_size;
    this->block_size_words = block_size / 64;
    this->block_size_bytes = block_size / 8;
    switch (block_size) {
    case 512:
        rounds = 10;
        IV[0] = 0x40;
        break;
    case 1024:
        rounds = 14;
        IV[0] = 0x80;
        break;
    }

    unsigned __int64 row = 0xf0f0f0f0f0f0f3;
    for (int j = 0; j < rounds; j++) {
        for (int i = 0; i < block_size_words; i++) {
            XOR_MATRIX[j][i] = (i << 4) ^ j;
            ADD_MATRIX[j][i] = row | ((unsigned __int64)(((block_size_words - 1 - i) << 4) ^ j) << 56);
        }
    }
    form_v_index(V_init_string, (unsigned char*)V_index);

    unsigned char v_init[] = { 1, 4, 5, 6, 7, 8 };
    m_col_precalc(v_init, 6, (unsigned char*)m_col_precalculation_matrix);
}

Kupyna::~Kupyna()
{
}

void Kupyna::s_box(unsigned char* message, unsigned char* key)
{
    for (int i = 0; i < block_size_bytes; i++)
        message[i] = key[(i % 4) * 256 + message[i]];
}

void Kupyna::xor_rkey(unsigned __int64* message, unsigned __int64* key)
{
    for (int i = 0; i < block_size_words; i++)
        message[i] = message[i] ^ key[i];
}

void Kupyna::add_rkey(unsigned __int64* message, unsigned __int64* key)
{
    for (int i = 0; i < block_size_words; i++) {
        message[i] = message[i] + key[i];
    }
}

void Kupyna::s_row(unsigned char* message)
{
    const int rows = 8;
    int shift = -1;
    int columns = block_size_words;
    unsigned __int8* buffer = new unsigned __int8[rows * columns];
    for (int i = 0; i < rows; i++) {
        if (i % (rows / 8) == 0)
            shift++;
        if (block_size == 1024 && i == 7)
            shift = 11;
        for (int j = 0; j < columns; j++) {
            buffer[i + ((j + shift) % columns) * rows] = message[i + j * rows];
        }
    }
    for (int i = 0; i < rows * columns; i++)
        message[i] = buffer[i];
    delete[] buffer;
}

unsigned char Kupyna::multiply(unsigned char _a, unsigned char _b)
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

void Kupyna::m_col_precalc(unsigned char* v_init, int length, unsigned char* precalc_matrix)
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

void Kupyna::m_col(unsigned char* message, unsigned char* s, unsigned char* v_indexes)
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

void Kupyna::form_v_index(unsigned char* init_string, unsigned char* result)
{
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            result[i * 8 + (j + i) % 8] = init_string[j];
}

void Kupyna::output(unsigned __int64* state, int n)
{
    unsigned char* a = (unsigned char*)state;
    std::cout << std::hex;
    for (int i = 0; i < n; i++) {
        if (i % 8 == 0)
            std::cout << "  ";
        std::cout << std::setw(2) << std::setfill('0') << (int)a[i];
        if (i % 32 == 31)
            std::cout << '\n';
    }
}

void Kupyna::encipher_round(unsigned __int64* state)
{
    s_box((unsigned char*)state, (unsigned char*)s);
    s_row((unsigned char*)state);
    m_col((unsigned char*)state, (unsigned char*)m_col_precalculation_matrix, (unsigned char*)V_index);
}

void Kupyna::xor_encipher(unsigned __int64* message)
{
    for (int i = 0; i < rounds; i++) {
        xor_rkey(message, XOR_MATRIX[i]);
        encipher_round(message);
    }
}

void Kupyna::add_encipher(unsigned __int64* message)
{
    for (int i = 0; i < rounds; i++) {
        add_rkey(message, ADD_MATRIX[i]);
        encipher_round(message);
    }
}

void Kupyna::hash_itteration(unsigned __int64* message, unsigned __int64* state, unsigned __int64* buffer)
{
    memcpy(buffer, message, block_size_bytes);
    xor_rkey(buffer, state);
    xor_encipher(buffer);
    xor_rkey(state, buffer);
    memcpy(buffer, message, block_size_bytes);
    add_encipher(buffer);
    xor_rkey(state, buffer);
}

void Kupyna::hash(unsigned char* message, long long bit_length, unsigned char* result, int result_len_byte)
{
    int number_of_blocks = bit_length / block_size;

    unsigned __int64* state = new unsigned __int64[block_size_words];
    unsigned __int64* buffer1 = new unsigned __int64[block_size_words];
    unsigned __int64* buffer2 = new unsigned __int64[block_size_words];

    memcpy(state, IV, block_size_bytes);

    for (int i = 0; i < number_of_blocks; i++) {
        hash_itteration((unsigned __int64*)(message + i * block_size_bytes), state, buffer1);
    }
    /*std::cout << '\n' << "block_0:" << '\n';
	output(state, 64);*/

    int last_block_length = bit_length % block_size;
    memset(buffer1, 0, block_size_bytes);
    if (last_block_length) {
        memcpy(buffer1, message + number_of_blocks * block_size_bytes, last_block_length / 8);
        *(((unsigned char*)buffer1) + (bit_length % block_size) / 8) = 0x80;
        if (last_block_length + 97 <= block_size) {
            unsigned __int64* p = (unsigned __int64*)(((unsigned char*)buffer1) + (block_size_bytes - 12));
            *p = bit_length;
            hash_itteration(buffer1, state, buffer2);
        } else {
            hash_itteration(buffer1, state, buffer2);
            memset(buffer1, 0, block_size_bytes);
            unsigned __int64* p = (unsigned __int64*)(((unsigned char*)buffer1) + (block_size_bytes - 12));
            *p = bit_length;
            hash_itteration(buffer1, state, buffer2);
        }
    } else {
        buffer1[0] = 0x80;
        unsigned __int64* p = (unsigned __int64*)(((unsigned char*)buffer1) + (block_size_bytes - 12));
        *p = bit_length;
        hash_itteration(buffer1, state, buffer2);
    }
    /*std::cout << '\n' << "padding:" << '\n';
	output(buffer1, 64);*/

    memcpy(buffer1, state, block_size_bytes);
    xor_encipher(buffer1);
    xor_rkey(state, buffer1);

    memcpy(result, (unsigned __int8*)state + (block_size_bytes - result_len_byte), result_len_byte);
    delete[] state;
    delete[] buffer1;
    delete[] buffer2;
}