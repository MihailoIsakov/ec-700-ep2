#include <stdio.h>
#include <stdlib.h>     /* malloc, free, rand */

int main ()
{
    int i,n,k;
    char * buffer;

    i=1500000000;
    //i = 100;
    k=1500000000;

    int mallocinput=i+k;
    buffer = (char*) malloc (mallocinput+1);

    printf("Successfully finished!\n");

    return 0;
}
