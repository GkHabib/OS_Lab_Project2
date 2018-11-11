#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"

int main(int argc, char const *argv[])
{
    int pid = atoi(argv[1]);
    int sys_num = atoi(argv[2]);
    get_count(pid, sys_num);
    return 0;
}
