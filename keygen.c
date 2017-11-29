#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void error(const char* msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char* argv[])
{
    srand(time(NULL));
    int i;
    int randNum;
    
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(0);
    }
    
    for (i = 0; i < atoi(argv[1]); i++)
    {
        randNum = rand() % 27;
        if (randNum < 26)
        {
            printf("%c", randNum + 65);
        }
        else
        {
            printf(" ");
        }
    }
    printf("\n");
}