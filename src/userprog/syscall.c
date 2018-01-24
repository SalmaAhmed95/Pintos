#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <threads/vaddr.h>
#include <lib/user/syscall.h>
#include <threads/synch.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"

#define OFFSET 4

static void syscall_handler(struct intr_frame *);

static bool is_valid_esp(void *esp, int args_count);

static void sys_halt(void);

static void sys_exit(int status);

static pid_t sys_exec(const char *cmd_line);

static int sys_wait(pid_t pid);

static bool sys_create(const char *file, unsigned initial_size);

static bool sys_remove(const char *file);

static int sys_open(const char *file);

static int sys_filesize(int fd);

static int sys_read(int fd, void *buffer, unsigned size);

static int sys_write(int fd, const void *buffer, unsigned size);

static void sys_seek(int fd, unsigned position);

static unsigned sys_tell(int fd);

static void sys_close(int fd);

void close_all_files(void);

void
syscall_init(void) {

    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    //check if f->esp is a valid pointer
    if (is_valid_esp(f->esp, 4)) {
        switch (*(int *) f->esp) {
            case SYS_HALT :
                sys_halt();
                break;
            case SYS_EXIT : {

                int status = *(int *) (f->esp + OFFSET);
                sys_exit(status);
                f->esp += OFFSET;
                break;
            }
            case SYS_EXEC : {
                const char *cmd_line = *(char **) (f->esp + OFFSET);
                if (is_valid_ptr(cmd_line) && is_valid_ptr(cmd_line + strlen(cmd_line) + 1)) {

                    f->eax = (uint32_t) sys_exec(cmd_line);
                } else {
                    terminate_process();
                }
                f->esp += OFFSET;
                break;
            }
            case SYS_WAIT : {
                pid_t pid = *(pid_t *) (f->esp + OFFSET);
                f->eax = (uint32_t) sys_wait(pid);

                f->esp += OFFSET;
                break;
            }
            case SYS_CREATE : {
                const char *file_name = *(char **) (f->esp + OFFSET);
                unsigned initial_size = *(unsigned *) (f->esp + 2 * OFFSET);
                //TODO: && is_valid_ptr(initial_size) //check validity of size not null ..negative and stuff
                if (is_valid_ptr(file_name)) {
                    lock_acquire(&file_sys_lock);
                    f->eax = (uint32_t) sys_create(file_name, initial_size);
                    lock_release(&file_sys_lock);
                } else {
                    terminate_process();
                }
                f->esp += (2 * OFFSET);
                break;
            }
            case SYS_REMOVE : {
                const char *file_name = *(char **) (f->esp + OFFSET);
                if (is_valid_ptr(file_name)) {
                    lock_acquire(&file_sys_lock);
                    f->eax = (uint32_t) sys_remove(file_name);
                    lock_release(&file_sys_lock);
                } else {
                    terminate_process();
                }
                f->esp += OFFSET;
                break;
            }
            case SYS_OPEN : {
                const char *file_name = *(char **) (f->esp + OFFSET);
                if (is_valid_ptr(file_name)) {
                    lock_acquire(&file_sys_lock);
                    f->eax = (uint32_t) sys_open(file_name);
                    lock_release(&file_sys_lock);
                } else {
                    terminate_process();
                }
                f->esp += OFFSET;
                break;
            }
            case SYS_FILESIZE : {
                int fd = *(int *) (f->esp + OFFSET);
                lock_acquire(&file_sys_lock);
                f->eax = (uint32_t) sys_filesize(fd);
                lock_release(&file_sys_lock);
                f->esp += OFFSET;
                break;
            }
            case SYS_READ : {
                int fd = *(int *) (f->esp + OFFSET);
                void *buffer = *(void **) (f->esp + 2 * OFFSET);   //check ptrs
                unsigned size = *(unsigned *) (f->esp + 3 * OFFSET);
                //check whole buffer (start , end)
                if (is_valid_ptr(buffer) && is_valid_ptr(buffer + size - 1)) {
                    lock_acquire(&file_sys_lock);
                    f->eax = (uint32_t) sys_read(fd, buffer, size);
                    lock_release(&file_sys_lock);
                } else
                    terminate_process();
                f->esp += (3 * OFFSET);
                break;

            }
            case SYS_WRITE : {
                int fd = *(int *) (f->esp + OFFSET);
                void *buffer = *(void **) (f->esp + 2 * OFFSET);
                unsigned size = *(unsigned *) (f->esp + 3 * OFFSET);
                //check whole buffer (start , end)
                if (is_valid_ptr(buffer) && is_valid_ptr(buffer + size - 1)) {
                    lock_acquire(&file_sys_lock);
                    f->eax = (uint32_t) sys_write(fd, buffer, size);
                    lock_release(&file_sys_lock);
                } else
                    terminate_process();
                f->esp += (3 * OFFSET);
                break;
            }
            case SYS_SEEK : {

                int fd = *(int *) (f->esp + OFFSET);
                unsigned position = *(unsigned *) (f->esp + 2 * OFFSET);
                lock_acquire(&file_sys_lock);
                sys_seek(fd, position);
                lock_release(&file_sys_lock);
                f->esp += (2 * OFFSET);
                break;

            }
            case SYS_TELL : {
                int fd = *(int *) (f->esp + OFFSET);
                lock_acquire(&file_sys_lock);
                f->eax = (uint32_t) sys_tell(fd);
                lock_release(&file_sys_lock);
                f->esp += OFFSET;
                break;


            }
            case SYS_CLOSE : {
                int fd = *(int *) (f->esp + OFFSET);
                lock_acquire(&file_sys_lock);
                sys_close(fd);
                lock_release(&file_sys_lock);
                f->esp += OFFSET;
                break;
            }
            default : {

                //TODO return error if syscall number is wrong
                break;
            }
        }
    } else {
        terminate_process();
    }
}

static void sys_halt(void) {
    shutdown_power_off();
}

void sys_exit(int status) {
    set_status(status);
    struct list_elem *e;
    struct thread *current = thread_current();
    for (e = list_begin(&current->locks_held); e != list_end(&current->locks_held); e = list_next(e))
        lock_release(list_entry (e, struct lock, elem));

    lock_acquire(&file_sys_lock);
    close_all_files();
   lock_release(&file_sys_lock);

    release_children();
    printf("%s: exit(%d)\n", thread_current()->name, status);
    struct thread *parent = thread_current()->parent;
    if (parent != NULL && parent->status != THREAD_DYING)
        sema_up(&thread_current()->pid_entry_by_parent->wait_semaphore);
    thread_exit();
}

pid_t sys_exec(const char *cmd_line) {
    return process_execute(cmd_line);
}

int sys_wait(pid_t pid) {
    //as pid is the same as tid as in pintos No multi-threaded process allowed
    return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size) {
    bool success = filesys_create(file, initial_size);
    return success;
}

bool sys_remove(const char *file) {

    bool success = filesys_remove(file);

    return success;
}


int sys_open(const char *file) {

    struct file *file_ptr = filesys_open(file);
    if (!file_ptr) {
        return -1;
    }
    int fd = insert_into_fdt(file_ptr);

    return fd;
}

int sys_filesize(int fd) {

    struct file *file_ptr = get_file(fd);
    //no file with this fd exists
    if (file_ptr == NULL) {
        return -1;
    }
    int size = file_length(file_ptr);

    return size;

}

int sys_read(int fd, void *buffer, unsigned size) {

    if (fd == STDIN_FILENO) {
        //this is the type returned by input_getc()
        uint8_t *in_buffer = (uint8_t *) buffer;
        for (int i = 0; i < size; i++) {
            in_buffer[i] = input_getc();
        }
        return size;
    }
    struct file *file_ptr = get_file(fd);
    if (file_ptr == NULL) {
        return -1;
    }
    int bytes_read = file_read(file_ptr, buffer, size);

    return bytes_read;
}

//check breaking long bufs in case of FILENO and do we need to lock on console as done in files??
int sys_write(int fd, const void *buffer, unsigned size) {

    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }
    struct file *file_ptr = get_file(fd);
    if (file_ptr == NULL) {
        return -1;
    }
    int bytes_written = file_write(file_ptr, buffer, size);
    return bytes_written;
}

void sys_seek(int fd, unsigned position) {

    struct file *file_ptr = get_file(fd);
    if (file_ptr == NULL) {
        return;
    }
    file_seek(file_ptr, position);

}

unsigned sys_tell(int fd) {

    struct file *file_ptr = get_file(fd);
    if (file_ptr == NULL) {
        return 0;  //TODO check this case bec i can not return -1 in unsigned
    }
    off_t position = file_tell(file_ptr);

    return (unsigned) position;
}

void sys_close(int fd) {
    //remove fd of this file from list of open files for a process
    struct list_elem *e;
    struct thread *current = thread_current();
    e = list_begin(&current->fdt);

    while (e != list_end(&current->fdt)) {
        struct fdt_entry *req_entry;
        req_entry = list_entry (e, struct fdt_entry, elem);
        if (req_entry->fd == fd) {
            file_close(get_file(fd));
            struct list_elem *prev;
            prev = e;
            e = list_next(prev);
            list_remove(prev);
            free(req_entry);
            break;
        }
    }
}

bool is_valid_ptr(void *ptr) {
    if (ptr == NULL)
        return false;
    if (ptr >= PHYS_BASE)
        return false;
    if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
        return false;
    return true;
}

static bool is_valid_esp(void *esp, int args_count) {
    for (int i = 0; i < args_count; i++)
        if (!is_valid_ptr(esp + OFFSET * i))
            return false;
    return true;
}

 void terminate_process(void) {
    sys_exit(-1);
}

void close_all_files(){
    struct list_elem *e;
    struct thread *current = thread_current();
    e = list_begin(&current->fdt);

    while( e != list_end(&current->fdt)) {
        struct fdt_entry *req_entry;
        req_entry = list_entry (e, struct fdt_entry, elem);
        int fd=req_entry->fd;
        file_close(get_file(fd));
        struct list_elem *prev;
        prev = e;
        e = list_next(prev);
        list_remove(prev);
        free(req_entry);

    }
}

void release_children(){
    struct list_elem *e;
    struct thread *current = thread_current();
    e = list_begin(&current->children);
    while( e != list_end(&current->children)) {
        struct pid_entry *child;
        child = list_entry (e, struct pid_entry, elem);

        struct list_elem *prev;
        prev = e;
        e = list_next(prev);
        list_remove(prev);
        free(child);

    }
}