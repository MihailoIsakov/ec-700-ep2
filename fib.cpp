#include <iostream>

int main() {
    
    int input;

    std::cout << "Enter number of Fibbonacci numbers:";
    std::cin  >> input;
    std::cout << std::endl;

    int a = 1;
    int b = 1;
    for (int i = 0; i < input; i++) {
        int c = a + b;
        b = a;
        a = c;

        std::cout << c << ", ";
    }

    std::cout << std::endl;

    return 0;
}
