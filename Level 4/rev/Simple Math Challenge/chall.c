#include <stdio.h>

int check(int n)
{
    int i;i^=i;i|=2;
    if(n<=0)goto b;
    if(n&1&&!(n>>1))goto b;
    c:if(i*i>n)goto a;if(!(n%i))goto b;i++;goto c;
    a:return 1;
    b:return 0;
}

int main(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    int coeff[3];
    printf("Input: ");
    for (int i = 0; i < 3; i++)
        scanf("%4d", &coeff[i]);
    if (coeff[1] == 0 && coeff[2] == 0)
    {
        printf("Wrong!\n");
        return 0;
    }
    for (int i = 0; i < 80; i++)
    {
        if (!check(coeff[0]))
        {
            printf("Wrong!\n");
            return 0;
        }
        coeff[0] += coeff[1];
        coeff[1] += coeff[2];
    }
    printf("Correct!\n");
    char flag[32];
    FILE* file = fopen("flag", "r");
    fgets(flag, sizeof(flag), file);
    printf("%s\n", flag);
    return 0;
}