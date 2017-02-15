#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

    int a = 1, b = 1, c = 0;

    int n = atoi(argv[1]);
    
    if (n == 0 || n == 1) {
        printf("%d\n", 1);
        return 0;
    }

    for (int i = 2; i <= n; i++) {
        c = a + b;
        b = a;
        a = c;
    }

    printf("%d\n", c);

    return 0;
}
