#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

int check(int seed) {
    int i = seed;
    int v9 = 0;
    while (i) {
        ++v9;
        i &= i - 1;
    }
    if (v9 == 10) return 1;
    else return 0;
}

unsigned char md5res[100];
char ans[100];

int have_a_try(int seed) {
    MD5_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    srand(seed);
    MD5_Init(&ctx);
    int i;
    char s[10];
    for (i = 0; i < 30; i++) {
        int t = rand() % 1000;
        printf("%d ", t);
        sprintf(s, "%d", t);
        MD5_Update(&ctx, s, strlen(s));
    }
    putchar('\n');
    MD5_Final(md5res, &ctx);
    for (i = 0; i < 16; i++) {
        sprintf(ans + 2 * i, "%02x", md5res[i]);
    }
    if ( !strcmp(ans, "5eba99aff105c9ff6a1a913e343fec67") ) {
        return 1;
    }
    puts(ans);
    return 0;
}

int main() {
    int i;
    for (i = 0; i < 0xffff; i++) {
        if (check(i)) {
            printf("try %d... ", i);
            if (have_a_try(i)) {
                puts("Success!!!");
                exit(0);
            } else {
                puts("Fail");
            }
        }
    }
    return 0;
}
