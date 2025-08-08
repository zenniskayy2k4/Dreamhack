// gcc main.c -o main
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

size_t value[2];

void win()
{
    system("/bin/sh");
}

int main()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("[wheat-and-barley]\n");
    printf("They all start from a seed...: %p\n", value);

    size_t off[2];

    printf("Wheat\n");
    printf("Where: ");
    scanf("%lld", (long long int *) &off[0]);
    
    if (off[0] > 0x2000) {
        printf("Wrong Location!\n");
        return 0;
    }

    printf("Count: ");
    scanf("%lld", (long long int *) &value[0]);
    *(size_t *)((size_t) stdout + off[0]) = value[0];


    printf("Barley\n");
    printf("Where: ");
    scanf("%lld", (long long int *) &off[1]);
    
    if (off[1] > 0x2000) {
        printf("Wrong Location!\n");
        return 0;
    }

    printf("Count: ");
    scanf("%lld", (long long int *) &value[1]);
    *(size_t *)((size_t) stdout + off[1]) = value[1];


    printf("Harvest Result: ");
    size_t result[2] = {off[0] * value[0] % 100, off[1] * value[1] % 100};
    printf("Wheat: %ld, Barley: %ld\n", result[0], result[1]);

    if (result[0] == 99 && result[1] == 99) {
        printf("Good!\n");
    } else {
        printf("No!\n");
    }

    return 0;
}