#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  int array[5];

  if(argc < 6){
    printf(1, "error: at least 5 number as argument is needed.\n");
    exit();
  }
  for(i=1; i<6; i++)
    array[i-1] = atoi(argv[i]);

  

  printf(1, "pid: %d\n", getpid());
  exit();
}
