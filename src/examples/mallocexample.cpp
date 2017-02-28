
#include <stdio.h>      /* printf, scanf, NULL */
#include <stdlib.h>     /* malloc, free, rand */

int main ()
{
short  int i,n,k;
  char * buffer;

i=32000;
k=768;

short int mallocinput=i+k;
  printf("input is %d \n",mallocinput);
  printf ("How long do you want the string?\n ");
  printf( "%d should be fine \n ",mallocinput); 
// scanf ("%d", &i);

  buffer = (char*) malloc (mallocinput+1);
  if (buffer==NULL) exit (1);

  for (n=0; n<i; n++)
    buffer[n]=rand()%26+'a';
  buffer[i]='\0';

  printf ("Random string: %s\n",buffer);
  free (buffer);

  return 0;

}
