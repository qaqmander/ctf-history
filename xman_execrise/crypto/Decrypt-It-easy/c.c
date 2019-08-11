#include <stdio.h>
#include <stdlib.h>

int main() {
    int i;
    for (i = 0; i < 1000; i += 100) {
        srand(i);
        int j;
        printf("%d ", i);
        for (j = 0; j < 10; j++) printf("%d ", rand() & 0xff);
        putchar('\n');
    }
    return 0;
}
