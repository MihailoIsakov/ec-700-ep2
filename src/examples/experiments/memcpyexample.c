/* memcpy example */
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
struct {
  char name[40];
  int age;
} person, person_copy;

int main ()
{
   char src[50] = "http://www.tutorialspoint.com";
   char dest[50];
int i=5;
int k=3;
i=i+k;
   printf("Before memcpy dest = %s\n", dest);
   memcpy(dest, src, i+1);
printf("HI");
   printf("After memcpy dest = %s\n", dest);
   memcpy(dest, src, strlen(src)+1);

  return 0;
}
