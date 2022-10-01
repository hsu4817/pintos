#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/mmu.h"
#include "threads/init.h"
#include <list.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/kernel/stdio.h"
#include "userprog/process.h"
#include "lib/string.h"
#include "devices/input.h"



void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct file* get_file_with_fd (int fd);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	lock_init(&syslock);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_no = (int) f->R.rax;
	enum intr_level old_level;
	old_level = intr_disable ();

	switch (syscall_no) {
		case SYS_HALT:
			halt ();
			break;
		case SYS_EXIT:
			exit ((int) f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork ((char *) f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec ((char *) f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait ((int) f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create ((char *) f->R.rdi, (unsigned int) f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove ((char *) f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open ((char *) f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize ((int) f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read ((int) f->R.rdi, (void *) f->R.rsi, (unsigned int) f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write ((int) f->R.rdi, (void *) f->R.rsi, (unsigned int) f->R.rdx);
			break;
		case SYS_SEEK:
			seek ((int) f->R.rdi, (unsigned int) f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell ((int) f->R.rdi);
			break;
		case SYS_CLOSE:
			close ((int) f->R.rdi);
			break;
		default:
			printf ("Unknown syscall number %d.\n", syscall_no);
			thread_exit ();
	}
	intr_set_level (old_level);
}


void halt (void){
	power_off ();
	printf("must not be called");
}

void exit (int status){
	//process exit 실패했을 경우도 생각????
	thread_current()->exit_status = status;
	thread_exit();
}

tid_t fork (const char *thread_name, struct intr_frame *if_){
	tid_t forked_child = process_fork(thread_name, if_);
	if (forked_child == TID_ERROR) {
		return -1;
	}
	else {
		return forked_child;
	}
}

int exec (const char *cmd_line){
	intr_enable ();
	char *fn_copy = palloc_get_page (0);
	if (fn_copy == NULL) exit (-1);
	strlcpy (fn_copy, cmd_line, PGSIZE);
	if (process_exec (fn_copy) == -1) exit (-1);
}

int wait (tid_t pid){
	int pid_ = pid;
	// printf ("Wait call for %d.\n", pid);
	return process_wait (pid_);
}

bool create (const char *file, unsigned initial_size) {
	if (file == NULL) exit (-1);
	if (*file == '\0') return false;

	lock_acquire(&syslock);
	bool create_bool;

	intr_enable ();
	create_bool = filesys_create (file, initial_size);
	lock_release(&syslock);
	return create_bool;
}

bool remove (const char *file) {
	if (file == NULL) exit (-1);
	if (*file == '\0') return false;

	lock_acquire(&syslock);
	bool remove_bool;

	intr_enable ();
	remove_bool =  filesys_remove (file);
	lock_release(&syslock);
	return remove_bool;
}


int open (const char *file) {
	struct file *FD;
	struct fdesc *fd = malloc (sizeof(struct fdesc));
	struct thread *curr = thread_current ();

	if (file == NULL) exit(-1);
	if (*file == '\0') return -1;

	lock_acquire(&syslock);

	intr_enable ();
	FD = filesys_open (file);
	if (FD == NULL) {
		return -1;
	}
	enum intr_level old_level;
	old_level = intr_disable ();

	fd->desc_no = list_entry(list_rbegin (&curr->desc_table), struct fdesc, elem)->desc_no + 1;
	fd->file = FD;
	list_push_back (&curr->desc_table, &fd->elem);

	intr_set_level (old_level);
	lock_release(&syslock);
	return fd->desc_no;
}

struct file*
get_file_with_fd (int fd){
	if (fd == 0 || fd == 1) {
		return false;
	}
	struct thread *curr = thread_current ();
	struct list_elem *i;
	for (i = list_begin (&curr->desc_table); i != list_end (&curr->desc_table); i = list_next (i)) {
		if (list_entry (i, struct fdesc, elem)->desc_no == fd) {
			return list_entry (i, struct fdesc, elem)->file;
		}
	}
	return NULL;
}


int filesize (int fd) {
	intr_enable ();

	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	return (int) file_length (file);
}

int read (int fd, void *buffer, unsigned size) {
	if (fd == 0) return input_getc();
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;

	intr_enable ();
	return file_read (file, buffer, size);
}

int 
write (int fd, const void *buffer, unsigned length) {
	if (fd == 1) {
		putbuf (buffer, length);
		return length;
	}
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	
	intr_enable ();
	return (int) file_write (file, buffer, length);
}

void
seek (int fd, unsigned position) {
	intr_enable ();

	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return;
	
	file_seek (file, position);
}

unsigned tell (int fd) {
	intr_enable ();

	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;

	return file_tell (file);
}

void close (int fd) {
	
	if (fd == 0 || fd == 1) {
		return;
	}
	struct fdesc *fd_ = NULL;
	struct thread *curr = thread_current ();
	struct list_elem *i;
	for (i = list_begin (&curr->desc_table); i != list_end (&curr->desc_table); i = list_next (i)) {
		if (list_entry (i, struct fdesc, elem)->desc_no == fd) {
			fd_ = list_entry (i, struct fdesc, elem);
			break;
		}
	}
	if (i == list_end (&curr->desc_table)) {
		return;
	}
	else {
		list_remove (&fd_->elem);
		intr_enable ();
		file_close (fd_->file);
	}
}


