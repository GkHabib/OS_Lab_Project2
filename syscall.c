#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "syscall.h"

// User code makes a system call with INT T_SYSCALL.
// System call number in %eax.
// Arguments on the stack, from the user call to the C
// library system call function. The saved user %esp points
// to a saved program counter, and then the first argument.

// Fetch the int at addr from the current process.
int
fetchint(uint addr, int *ip)
{
  struct proc *curproc = myproc();

  if(addr >= curproc->sz || addr+4 > curproc->sz)
    return -1;
  *ip = *(int*)(addr);
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Doesn't actually copy the string - just sets *pp to point at it.
// Returns length of string, not including nul.
int
fetchstr(uint addr, char **pp)
{
  char *s, *ep;
  struct proc *curproc = myproc();

  if(addr >= curproc->sz)
    return -1;
  *pp = (char*)addr;
  ep = (char*)curproc->sz;
  for(s = *pp; s < ep; s++){
    if(*s == 0)
      return s - *pp;
  }
  return -1;
}

// Fetch the nth 32-bit system call argument.
int
argint(int n, int *ip)
{
  return fetchint((myproc()->tf->esp) + 4 + 4*n, ip);
}

// Fetch the nth word-sized system call argument as a pointer
// to a block of memory of size bytes.  Check that the pointer
// lies within the process address space.
int
argptr(int n, char **pp, int size)
{
  int i;
  struct proc *curproc = myproc();
 
  if(argint(n, &i) < 0)
    return -1;
  if(size < 0 || (uint)i >= curproc->sz || (uint)i+size > curproc->sz)
    return -1;
  *pp = (char*)i;
  return 0;
}

// Fetch the nth word-sized system call argument as a string pointer.
// Check that the pointer is valid and the string is nul-terminated.
// (There is no shared writable memory, so the string can't change
// between this check and being used by the kernel.)
int
argstr(int n, char **pp)
{
  int addr;
  if(argint(n, &addr) < 0)
    return -1;
  return fetchstr(addr, pp);
}

extern int sys_chdir(void);
extern int sys_close(void);
extern int sys_dup(void);
extern int sys_exec(void);
extern int sys_exit(void);
extern int sys_fork(void);
extern int sys_fstat(void);
extern int sys_getpid(void);
extern int sys_kill(void);
extern int sys_link(void);
extern int sys_mkdir(void);
extern int sys_mknod(void);
extern int sys_open(void);
extern int sys_pipe(void);
extern int sys_read(void);
extern int sys_sbrk(void);
extern int sys_sleep(void);
extern int sys_unlink(void);
extern int sys_wait(void);
extern int sys_write(void);
extern int sys_uptime(void);
extern int sys_invoked_syscalls(void);
extern int sys_sort_syscalls(void);

static int (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_invoked_syscalls]    sys_invoked_syscalls,
[SYS_sort_syscalls]       sys_sort_syscalls,
};


struct _my_syscall_history
{
  uint num;
  struct _my_syscall_history* next;
  struct _my_syscall_history* prev;
};

struct _my_history
{
  uint pid;
  struct _my_history *next;
  struct _my_syscall_history* calls;
};

struct _my_history* _History = 0;

struct _my_history* find_history_of_process(uint pid) {
  if(!_History)
    return 0;
  struct _my_history* curr = _History;
  while(1) {
    if(curr->pid == pid)
      return curr;
    if(curr->next)
      curr = curr->next;
    else
      return 0;
  }

}

struct _my_history* 
_add_history(uint pid) {
  // struct _my_history* new_node = (struct _my_history*)malloc(sizeof(struct _my_history));
  struct _my_history* new_node = (struct _my_history*)kalloc();
  memset(new_node, 0, sizeof(struct _my_history));
  if(!new_node)
  {
    cprintf("failed to save history.\n");
    return 0;
  }
  new_node->pid = pid;
  new_node->next = 0;
  new_node->calls = 0;

  cprintf("newnode is : %p \n", new_node);
  cprintf("_History is : %p \n", _History);
  struct _my_history* curr = _History;
  if(!curr) {
    _History = new_node;
  }
  else {
    while(curr->next)
      curr = curr->next;
    curr->next = new_node;
  }

  return new_node;
  
}

void 
_add_call(struct _my_history* history, int num) {
  // struct _my_syscall_history* new_node = (struct _my_syscall_history*)malloc(sizeof(struct _my_syscall_history));
  struct _my_syscall_history* new_node = (struct _my_syscall_history*)kalloc();
  if(!new_node)
  {
    cprintf("failed to save history.\n");
    return;
  }
  new_node->num = num;
  new_node->next = 0;
  new_node->prev = 0;

  if(!history->calls) {
    history->calls = new_node;
  }
  else {
    struct _my_syscall_history* curr = history->calls;
    while(curr->next)
      curr = curr->next;
    curr->next = new_node;
    new_node->prev = curr;
  }
  
}

void
syscall_called_event(uint pid, int num)
{
  struct _my_history* this_pid = find_history_of_process(pid);
  if(!this_pid) {
    this_pid = _add_history(pid);
    if(!this_pid) {
      cprintf("failed to save history.\n");
      return;
    }
  }

  _add_call(this_pid, num);
}

int my_flag = 0;

void
syscall(void)
{
  int num;
  struct proc *curproc = myproc();

  num = curproc->tf->eax;


  if(my_flag) {
    syscall_called_event(curproc->pid, num);
  }


  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    curproc->tf->eax = syscalls[num]();
  } else {
    cprintf("%d %s: unknown sys call %d\n",
            curproc->pid, curproc->name, num);
    curproc->tf->eax = -1;
  }

  // if(my_flag) {
  //   cprintf("=== Start\n");
  //   struct _my_history* curr = _History;
  //   while(curr) {
  //     cprintf("PID: %d\n");
  //     struct _my_syscall_history* curr2 = curr->calls;
  //     while(curr2) {
  //       cprintf("\tSYSCALL %d\n", curr2->num);
  //       curr2 = curr2->next;
  //     }
  //     curr = curr->next; 
  //   }
  //   cprintf("=== END\n");
  // }
}


void 
print_invoked_syscalls(uint pid)
{
  my_flag = 1;
  struct _my_history* history = find_history_of_process(pid);
  cprintf("process pid is : %d\n", pid);
  cprintf("process pointer is : %p \n", history);
  if(!history) {
    cprintf("The process number %d never called any system call.\n", pid);
    return;
  }

  struct _my_syscall_history* curr = history->calls;
  while(curr) {
    cprintf("-> system call %d\n", curr->num);
    curr = curr->next;
  }

}

void print_invoked_processes()
{

}
// void swap(struct Node *a, struct Node *b) 
// { 
//     int temp = a->data; 
//     a->data = b->data; 
//     b->data = temp; 
// } 

void 
my_sort_syscalls(uint pid) {
  struct _my_history* history = find_history_of_process(pid);
  if(!history) {
    cprintf("The process number %d never called any system call.\n", pid);
    return;
  }

  // int swapped, i;
  // struct Node *ptr1; 
  // struct Node *lptr = NULL; 

  // /* Checking for empty list */
  // if (start == NULL) 
  //     return; 

  // do
  // { 
  //     swapped = 0; 
  //     ptr1 = start; 

  //     while (ptr1->next != lptr) 
  //     { 
  //         if (ptr1->data > ptr1->next->data) 
  //         {  
  //             swap(ptr1, ptr1->next); 
  //             swapped = 1; 
  //         } 
  //         ptr1 = ptr1->next; 
  //     } 
  //     lptr = ptr1; 
  // } 
  // while (swapped);
}

