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
#include "lib/user/syscall.h"

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
	printf ("system call!\n");
	thread_exit ();
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

pid_t fork(const char *thread_name){
	
	pid_t forked_child = process_fork(thread_name);

	//__dofork needed

	if(thread_current() == forked_child){
		return 0;
	}
	else{
		return forked_child;
	}
}

int exec (const char *cmd_line);

int wait (pid_t pid){

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

bool create (const char *file, unsigned initial_size);

bool remove (const char *file);

int open (const char *file);

int filesize (int fd);

int read (int fd, void *buffer, unsigned size);

int write (int fd, const void *buffer, unsigned size);

void seek (int fd, unsigned position);

unsigned tell (int fd);

void close (int fd);