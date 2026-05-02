#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int main(void) {
    char input[64];
    char flag[256];
    uint64_t bits;
    double value;
    FILE *fp;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("Send 16 hex digits.\n> 0x");
    fflush(stdout);

    if (!fgets(input, sizeof(input), stdin)) return 1;
    input[strcspn(input, "\n")] = '\0';

    if (strlen(input) != 16) {
        puts("bad: need 16 hex digits");
        return 1;
    }

    if (!strstr(input, "deadbeef")) {
        puts("bad: no substring");
        return 1;
    }

    bits = strtoull(input, NULL, 16);
    memcpy(&value, &bits, sizeof(value));

    if (!isnan(value)) {
        puts("bad: not nan");
        return 1;
    }

    fp = fopen("flag.txt", "r");
    if (!fp || !fgets(flag, sizeof(flag), fp)) {
        if (fp) fclose(fp);
        puts("bad: cannot read flag.txt");
        return 1;
    }

    fclose(fp);
    puts(flag);
    return 0;
}
