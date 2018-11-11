#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"

int main(int argc, char const *argv[])
{
    int pid = atoi(argv[1]);
    invoked_syscalls(pid);
    return 0;
}
