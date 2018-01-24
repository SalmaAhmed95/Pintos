#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <lib/stdbool.h>

void syscall_init (void);
void terminate_process(void);
bool is_valid_ptr(void *esp);
#endif /* userprog/syscall.h */
