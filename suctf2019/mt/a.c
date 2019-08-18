#include <stdio.h>
#include <stdlib.h>

unsigned int convert(unsigned int m) {
    m = m ^ m >> 13;
    m = m ^ m << 9 & 2029229568ll;
    m = m ^ m << 17 & 2245263360ll;
    m = m ^ m >> 19;
    return m;
}

int main() {
    unsigned int i;
    for (i = 0; i <= (unsigned int)0xffffffffll; i++) {
        if (i & 0xfffff == 0)
            printf("%u\n", i);
        if (convert(i) == (unsigned int)2854351778ll) {
            printf("%u", i);
            break;
        }
    }
    return 0;
}
