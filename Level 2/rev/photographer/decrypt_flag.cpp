// decrypt_flag.cpp
#include <bits/stdc++.h>
using namespace std;

static inline uint8_t rol(uint8_t x, unsigned k) {
    k &= 7;
    if (k == 0) return x;
    return (uint8_t)((x << k) | (x >> (8 - k)));
}
static inline uint8_t ror(uint8_t x, unsigned k) {
    k &= 7;
    if (k == 0) return x;
    return (uint8_t)((x >> k) | (x << (8 - k)));
}

int main(int argc, char** argv) {
    const string inName  = (argc >= 2 ? argv[1] : "flag.bmp.enc");
    const string outName = (argc >= 3 ? argv[2] : "flag.bmp");

    // read ciphertext
    ifstream in(inName, ios::binary);
    if (!in) {
        cerr << "Can't open input: " << inName << "\n";
        return 1;
    }
    vector<uint8_t> buf((istreambuf_iterator<char>(in)), {});
    in.close();

    // reproduce exact rand() sequence
    srand(0xbeef);

    for (size_t i = 0; i < buf.size(); ++i) {
        int r = rand();              // one rand() per byte, just like the encryptor
        uint8_t &b = buf[i];
        switch (i % 3) {
            case 0: {
                // enc = ROL4((r + ROL1(orig)) & 0xff)
                uint8_t t = ror(b, 4);
                uint8_t rol1_orig = (uint8_t)((t - (r & 0xff)) & 0xff);
                b = ror(rol1_orig, 1);
                break;
            }
            case 1: {
                // enc = ROR(orig, r % 8)
                unsigned k = (unsigned)(r % 8);
                b = rol(b, k);
                break;
            }
            case 2: {
                // enc = ((r ^ orig) - 0x18)
                b = (uint8_t)(((uint8_t)(b + 0x18)) ^ (uint8_t)r);
                break;
            }
        }
    }

    ofstream out(outName, ios::binary);
    if (!out) {
        cerr << "create file failed: " << outName << "\n";
        return 1;
    }
    out.write((char*)buf.data(), (streamsize)buf.size());
    out.close();

    cout << "Done. Wrote: " << outName << "\n";
    return 0;
}
