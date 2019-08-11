#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    int i = atoi(argv[1]);
        srand(i);
        int j;
        printf("%d ", i);
        for (j = 0; j < 10; j++) printf("%d ", rand() & 0xff);
        putchar('\n');
    return 0;
}
