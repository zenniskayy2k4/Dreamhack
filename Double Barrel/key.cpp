#include<cstdio>
#include<cstdint>
#include<cassert>

const size_t SIZE = 23738715/2;
uint64_t innerproduct(uint64_t a,uint64_t b){
    return __builtin_parityll(a&b);
}

// 48bit LFSR
class LFSR{
public:
    uint64_t poly;
    uint64_t state;
    LFSR(uint64_t _poly,uint64_t _seed){
        poly = _poly;
        state = _seed;
    }
    uint32_t bit(){
        assert((state>>48)==0);
        uint64_t out = ((state>>47)&1);
        uint64_t newbit = innerproduct(state,poly);
        state = ((state<<1)|newbit);
        state = (state&0xffffffffffffL);
        return out;
    }
};

uint32_t crc_append_bit(uint32_t crc,uint32_t bit){
    crc ^= bit;
    return (crc>>1)^(-(crc&1)&0xEDB88320);
}

uint32_t rk(LFSR& lfsr){
    uint32_t crc=0xffffffffL;
    for(int i=0;i<SIZE;i++){
        crc = crc_append_bit(crc,lfsr.bit());
    }
    return crc^0xffffffffL;
}

int main(int argc,char* argv[]){
    if(argc<3){
        printf("Usage: %s <poly> <seed>\n",argv[0]);
        return 0;
    }
    uint64_t poly,seed;
    sscanf(argv[1],"%lu",&poly);
    sscanf(argv[2],"%lu",&seed);
    LFSR lfsr(poly,seed);
    for(int i=0;i<16;i++){
        printf("%u\n",rk(lfsr));
        lfsr.bit();
        printf("%u\n",rk(lfsr));
    }
}