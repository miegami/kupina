#include "Kupyna.h"
#include <iomanip>
#include <iostream>

using namespace std;

void reverse(unsigned __int64& a)
{
    unsigned __int64 buf = 0;
    unsigned char* p2 = (unsigned char*)&buf;
    unsigned char* p1 = (unsigned char*)&a;
    for (int i = 0; i < 8; i++)
        p2[i] = p1[7 - i];
    a = buf;
}

void test256_512_512()
{
    unsigned __int64 INPUT[8] = { 0x0001020304050607, 0x08090A0B0C0D0E0F,
        0x1011121314151617, 0x18191A1B1C1D1E1F,
        0x2021222324252627, 0x28292A2B2C2D2E2F,
        0x3031323334353637, 0x38393A3B3C3D3E3F };

    for (int i = 0; i < 8; i++)
        reverse(INPUT[i]);
    Kupyna kupyna(512);

    unsigned __int64 HASH[4];

    cout << '\n'
         << "Plaintext:" << '\n';
    ;
    kupyna.output(INPUT, 64);
    kupyna.hash((unsigned __int8*)INPUT, 512, (unsigned __int8*)HASH, 32);
    cout << '\n'
         << "Ciphertext:";
    kupyna.output(HASH, 32);
    cout << '\n';
}

void test512_1024_1024()
{
    unsigned __int64 INPUT[16] = { 0x0001020304050607, 0x08090A0B0C0D0E0F,
        0x1011121314151617, 0x18191A1B1C1D1E1F,
        0x2021222324252627, 0x28292A2B2C2D2E2F,
        0x3031323334353637, 0x38393A3B3C3D3E3F,
        0x4041424344454647, 0x48494A4B4C4D4E4F, 0x5051525354555657, 0x58595A5B5C5D5E5F,
        0x6061626364656667, 0x68696A6B6C6D6E6F, 0x7071727374757677, 0x78797A7B7C7D7E7F };

    for (int i = 0; i < 16; i++)
        reverse(INPUT[i]);
    Kupyna kupyna(1024);

    unsigned __int64 HASH[8];

    cout << '\n'
         << "Plaintext:" << '\n';
    ;
    kupyna.output(INPUT, 128);
    kupyna.hash((unsigned __int8*)INPUT, 1024, (unsigned __int8*)HASH, 64);
    cout << '\n'
         << "Ciphertext:";
    kupyna.output(HASH, 64);
    cout << '\n';
}

void test512_1024_0()
{
    unsigned __int64 INPUT[16] = { 0 };

    Kupyna kupyna(1024);

    unsigned __int64 HASH[8];

    cout << '\n'
         << "Plaintext:" << '\n';
    kupyna.output(INPUT, 128);
    kupyna.hash((unsigned __int8*)INPUT, 0, (unsigned __int8*)HASH, 64);
    cout << '\n'
         << "Ciphertext:";
    kupyna.output(HASH, 64);
    cout << '\n';
}

void test(int message_len, int hash_len, int state_len)
{
    cout << dec << "State: " << state_len << ",  Input: " << message_len << ",  Hash: " << hash_len << hex;

    unsigned __int64 INPUT[16] = { 0x0001020304050607, 0x08090A0B0C0D0E0F,
        0x1011121314151617, 0x18191A1B1C1D1E1F,
        0x2021222324252627, 0x28292A2B2C2D2E2F,
        0x3031323334353637, 0x38393A3B3C3D3E3F,
        0x4041424344454647, 0x48494A4B4C4D4E4F, 0x5051525354555657, 0x58595A5B5C5D5E5F,
        0x6061626364656667, 0x68696A6B6C6D6E6F, 0x7071727374757677, 0x78797A7B7C7D7E7F };

    for (int i = 0; i < message_len / 64; i++)
        reverse(INPUT[i]);
    Kupyna kupyna(state_len);

    unsigned __int8* HASH = new unsigned __int8[hash_len / 8];

    cout << '\n'
         << "Input:" << '\n';
    ;
    kupyna.output(INPUT, message_len / 8);
    kupyna.hash((unsigned __int8*)INPUT, message_len, HASH, hash_len / 8);
    cout << '\n'
         << "Hash:\n";
    kupyna.output((unsigned __int64*)HASH, hash_len / 8);
    cout << '\n';
}

void test8(int message_len, int hash_len, int state_len)
{
    cout << dec << "State: " << state_len << ",  Input: " << message_len << ",  Hash: " << hash_len << hex;

    unsigned __int64 INPUT[1] = { 0xff00000000000000 };
    reverse(INPUT[0]);
    Kupyna kupyna(state_len);

    unsigned __int8* HASH = new unsigned __int8[hash_len / 8];

    cout << '\n'
         << "Input:" << '\n';
    ;
    kupyna.output(INPUT, 1);
    kupyna.hash((unsigned __int8*)INPUT, message_len, HASH, hash_len / 8);
    cout << '\n'
         << "Hash:\n";
    kupyna.output((unsigned __int64*)HASH, hash_len / 8);
    cout << '\n';
}

void main()
{
    test(512, 256, 512);
    test(1024, 256, 512);
    test(0, 256, 512);

    test(512, 512, 1024);
    test(1024, 512, 1024);
    test(0, 512, 1024);

    test8(8, 256, 512);
    test8(8, 512, 1024);
}