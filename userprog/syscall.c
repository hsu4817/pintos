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
#include "malloc.h"
#include "lib/kernel/stdio.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


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
	int syscall_no = f->R.rax;

	switch (syscall_no) {
		case SYS_HALT:
			halt ();
		case SYS_EXIT:
			exit ((int) f->R.rdi);
		case SYS_FORK:
			f->R.rax = fork ((char *) f->R.rdi, (struct intr_frame *) f->R.rsi);
		case SYS_EXEC:
			f->R.rax = exec ((char *) f->R.rdi);
		case SYS_WAIT:
			f->R.rax = wait ((int) f->R.rdi);
		case SYS_CREATE:
			f->R.rax = create ((char *) f->R.rdi, (unsigned int) f->R.rsi);
		case SYS_REMOVE:
			f->R.rax = remove ((char *) f->R.rdi);
		case SYS_OPEN:
			f->R.rax = open ((char *) f->R.rdi);
		case SYS_FILESIZE:
			f->R.rax = filesize ((int) f->R.rdi);
		case SYS_READ:
			f->R.rax = read ((int) f->R.rdi, (void *) f->R.rsi, (unsigned int) f->R.rdx);
		case SYS_WRITE:
			f->R.rax = write ((int) f->R.rdi, (void *) f->R.rsi, (unsigned int) f->R.rdx);
		case SYS_SEEK:
			seek ((int) f->R.rdi, (unsigned int) f->R.rsi);
		case SYS_TELL:
			f->R.rax = tell ((int) f->R.rdi);
		case SYS_CLOSE:
			close ((int) f->R.rdi);
		default:
			printf ("system call!\n");
			thread_exit ();
	}
}


void halt (void){
	power_off();
}

void exit (int status){

	//process exit 실패했을 경우도 생각????
	thread_current()->status = 0;
	thread_current()->parent->child_exit_status = status;
	thread_exit();
	
}

int fork (const char *thread_name, struct intr_frame *if_){
	tid_t forked_child = process_fork(thread_name, if_);
	if (forked_child == TID_ERROR) {
		return -1;
	}
	if(thread_current()->tid == forked_child){
		return 0;
	}
	else{
		return forked_child;
	}
}

int exec (const char *cmd_line){
	return process_exec (cmd_line);
}

int wait (tid_t pid){

	struct list_elem *i;
	int tag = 0;
	for (i = list_begin(&thread_current()->childs); i != list_end(&thread_current()->childs); i = list_next(i)){
		if(list_entry(i, struct thread, elem_child)->tid == pid){
			tag = 1;
			break;
		}
	} // 이거 하나로 될라나?

	if(tag == 0){
		return -1;
	}

	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
	return filesys_create (file, initial_size);
}

bool remove (const char *file) {
	return filesys_remove (file);
}


int open (const char *file) {
	struct file *FD;
	struct fdesc *fd = malloc (sizeof(struct fdesc));
	struct thread *curr = thread_current ();

	enum intr_level old_level;
	old_level = intr_disable ();
	FD = filesys_open (file);
	if (FD == NULL) {
		return -1;
	}
	list_entry(list_rbegin (&curr->desc_table), struct fdesc, elem);
	fd->desc_no = list_entry(list_rbegin (&curr->desc_table), struct fdesc, elem)->desc_no + 1;
	fd->file = FD;
	list_push_back (&curr->desc_table, &fd->elem);

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
	int fd_ = fd;
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	return (int) file_length (file);
}

int read (int fd, void *buffer, unsigned size) {
	if (fd == 0) return input_getc();
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;

	return file_read (file, buffer, size);
}

int 
write (int fd, const void *buffer, unsigned length) {
	if (fd == 1) {
		putbuf (buffer, length);
	}
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	return (int) file_write (file, buffer, length);
}

void
seek (int fd, unsigned position) {
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	
	file_seek (file, position);
}

unsigned tell (int fd) {
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;

	file_tell (file);
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
		file_close (fd_->file);
	}
}


