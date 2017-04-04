/* Sample C program illustrating the use of strcmp function */

#include<stdio.h>

#include<string>
using namespace std;

int main() {

    string str1 = "sarah";
    // diff at letter 2942
    string str2 = "sarah";

    int a;

    a += str1.compare(str2);

    if(a == 0)
    {
        printf("The strings are equal\n");
    }

    else
    {
        printf("The strings are not equal\n");
    }

    return 0;

}
