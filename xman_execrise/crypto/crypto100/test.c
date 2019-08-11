#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	if (argc != 3) {
		printf("USAGE: %s INPUT OUTPUT\n", argv[0]);
		return 0;
	}
	FILE* input  = fopen(argv[1], "rb");
	FILE* output = fopen(argv[2], "rb");
	if (!input || !output) {
		printf("Error\n");
		return 0;
	}
        char k[100];
	int c, p, q, t = 0;
	int i = 0;
	while ((p = fgetc(input)) != EOF, (q=fgetc(output))!=EOF) {
                c = q - p - i * i;
                while (c<0) c += 0x100;
                printf("%c %c %c\n", c^t, p, q);
//c = (p + (k[i % strlen(k)] ^ t) + i*i) & 0xff;
		t = p;
		i++;
//		fputc(c, output);
	}
        putchar('\n');
	return 0;
}
