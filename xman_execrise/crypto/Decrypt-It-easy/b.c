#include <stdio.h>
#include <stdlib.h>

int target[] = {189, 32, 190, 106, 182, 138, 28, 31};

int main() {
    int start = 1416667590;
    srand(start);
    int i;
    FILE *fr = fopen("./ecrypt1.bin", "rb");
    FILE *fw = fopen("./a.png", "wb");
    int ch;
    while ((ch = fgetc(fr)) != EOF) {
        fputc(ch ^ (rand() & 0xff), fw);
    }
    fclose(fr);
    fclose(fw);
    return 0;
}
