
//created by sadullah
//basic overflow; maximum signed value 32767, adding 1 results in overflow

#include <iostream>

int main() {

   int input,input2; //32767 -> maximum signed short value
   char d;
    std::cout << "Please enter two  numbers:";
    std::cin>>input>>input2;
    std::cout << std::endl;

    int x,y,z;
    signed short sum;
    signed short mul;

//basic math operations to be able to observe instructions; debugging purposes
for (int i=1;i<10;i++){
 x=i;
 y=i+1;
 z=x+y;
}

// here overflow exits,adding 1 to the max value ended with minus value
sum=input+input2;
std::cout<<"Sum finished..:";
std::cin>>d;
mul=input*input2;

std::cout<<"Summation is:";
std::cout<<(sum)<<std::endl;

std::cout<<"Multiplication is:";
std::cout<<(mul)<<std::endl;

   return 0;
}
