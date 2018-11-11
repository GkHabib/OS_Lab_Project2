#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"


void reverse(char str[], int length) 
{ 
    int start = 0; 
    int end = length -1; 
    while (start < end) 
    { 
        char a = *(str+start);
        *(str+start) = *(str+end);
        *(str+end) = a;
        start++; 
        end--; 
    } 
} 

char* itoa(int num, char* str, int base) 
{ 
    int i = 0; 
    int isNegative = 0; 
    if (num == 0) 
    { 
        str[i++] = '0'; 
        str[i] = '\0'; 
        return str; 
    } 
    if (num < 0 && base == 10) 
    { 
        isNegative = 1; 
        num = -num; 
    } 
    while (num != 0) 
    { 
        int rem = num % base; 
        str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0'; 
        num = num/base; 
    } 
    if (isNegative) 
        str[i++] = '-'; 
    str[i] = '\0';
    reverse(str, i); 
    return str; 
} 

int
main(int argc, char *argv[])
{
  char temp[10];

  write(1, "pid: ", 5);
  itoa(getpid(), temp, 10);
  write(1, temp, strlen(temp));
  write(1, "\n", 1);


  sort_syscalls(2);
  invoked_syscalls(2);
  exit();

  int array[5];

  

  if(argc < 6){
    write(1, "error: at least 5 number as argument is needed.\n", 48);
    exit();
  }
  for(int i=1; i<6; i++)
    array[i-1] = atoi(argv[i]);

  for(int i = 0; i<5; i++) {
    for(int j = i; j<5; j++) {
      if(array[i] > array[j]) {
        int x = array[i];
        array[i] = array[j];
        array[j] = x;
      }
    }
  }

  int fd = open("result.txt", O_CREATE | O_WRONLY);

  for(int i = 0; i<5; i++) {
    itoa(array[i], temp, 10);
    write(fd, temp, strlen(temp));
    write(fd, "\n", 1);
  }


  write(1, "pid: ", 5);
  itoa(getpid(), temp, 10);
  write(1, temp, strlen(temp));
  write(1, "\n", 1);

  exit();
}
