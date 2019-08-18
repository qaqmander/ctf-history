// gcc a.c -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <time.h>

unsigned char hexres[100];

void md5(char *s) {
    unsigned char res[100];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, s, strlen(s));
    MD5_Final(res, &ctx);
    int i;
    for (i = 0; i < 0x10; i++)
        sprintf(hexres + 2 * i, "%02x", res[i]);
}

char s[100];

int main(int argc, char *argv[]) {
    srand(time(0));
    memcpy(s + 6, argv[1], 4);
    int i;
    int tot = 0;
    while (1) {
        tot++;
        if (tot & 0xfff == 0) printf("%d\n", tot);
        for (i = 0; i < 6; i++) {
            s[i] = rand() & 0xff;
        }
        md5(s);
        if (!memcmp(hexres, argv[2], 5)) {
            puts(s);
            return 0;
        }
    }
    return 0;
}
