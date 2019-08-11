#include <stdio.h>
#include <stdlib.h>

int main() {
    srand(0);
    int i;
    putchar('[');
    for (i = 0; i < 50; i++) printf("%d,", rand() % 6 + 1);
    putchar(']');
    return 0;
}
