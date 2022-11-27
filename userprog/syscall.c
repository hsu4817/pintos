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


#include "devices/input.h"
#include "devices/timer.h"
#include "lib/string.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "vm/file.h"
#include "vm/vm.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"



void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct file* get_file_with_fd (int fd);
void update_dup (struct file*);
static bool ptr_is_writable (void *addr); 


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
	int syscall_no = (int) f->R.rax;
	enum intr_level old_level;
	old_level = intr_disable ();
	thread_current ()->rsp_stack_growth = f->rsp;

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
		case SYS_DUP2:
			f->R.rax = dup2 (f->R.rdi, f->R.rsi);
			break;
		case SYS_MMAP:
			f->R.rax = mmap (f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap (f->R.rdi);
			break;
		case SYS_CHDIR:
			f->R.rax = chdir (f->R.rdi);
			break;
		case SYS_MKDIR:
			f->R.rax = mkdir (f->R.rdi);
			break;
		case SYS_READDIR:
			f->R.rax = readdir (f->R.rdi, f->R.rsi);
			break;
		case SYS_ISDIR:
			f->R.rax = isdir (f->R.rdi);
			break;
		case SYS_INUMBER:
			f->R.rax = inumber (f->R.rdi);
			break;
		case SYS_SYMLINK:
			f->R.rax = symlink (f->R.rdi, f->R.rsi);
			break;
		default:
			printf ("Unknown syscall number %d.\n", syscall_no);
			thread_exit ();
	}
	intr_set_level (old_level);
}

bool chdir (const char *dir){
	bool success = false;
	file_lock_aquire ();
	success = filesys_chdir(dir);
	file_lock_release ();
	return success;
}

bool mkdir (const char *dir){
	bool success = false;
	file_lock_aquire ();
	success = filesys_mkdir(dir);
	file_lock_release ();
	return success;
}

bool readdir (int fd, char *name){
	if(isdir(fd) == 0) return false;

	struct dir *curr_dir = get_file_with_fd(fd);

	file_lock_aquire ();
	bool success = dir_sysreaddir(curr_dir, 15, name);
	file_lock_release ();
	return success;
}

bool isdir (int fd){
	struct thread *cur = thread_current ();
	struct list_elem *f;

	for (f = list_begin (&cur->desc_table); f != list_end (&cur->desc_table); f = list_next (f)) {
		if (list_entry (f, struct fdesc, elem)->desc_no == fd) {
			if (list_entry (f, struct fdesc, elem)->is_dir) return true;
			else return false;
		}
	}
	return false;
}

int inumber (int fd){
	if (isdir(fd)) {
		struct file *file = get_file_with_fd (fd);
		return inode_get_inumber (file_get_inode (file));
	}
	else {
		struct dir *dir = get_file_with_fd (fd);
		return inode_get_inumber (dir_get_inode (dir));
	}
}

int symlink (const char *target, const char *linkpath){
	
}

static bool ptr_is_writable (void *addr) {
	struct page *page = spt_find_page (&thread_current ()->spt, pg_round_down (addr));
	if (page == NULL) {
		return false;
	}
	return page->unit->writable;
}

void halt (void){
	intr_enable ();
	timer_sleep(10);
	power_off ();
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

	if (process_exec (fn_copy) == -1) exit (-1); //Free the page in process_exec () if exec fail.
}

int wait (tid_t pid){
	int pid_ = pid;
	// printf ("Wait call for %d.\n", pid);
	return process_wait (pid_);
}

bool create (const char *file, unsigned initial_size) {
	if (file == NULL) exit (-1);
	if (*file == '\0') return false;

	file_lock_aquire ();
	bool create_bool;

	intr_enable ();
	create_bool = filesys_create (file, initial_size);
	file_lock_release ();
	return create_bool;
}

bool remove (const char *file) {
	if (file == NULL) exit (-1);
	if (*file == '\0') return false;

	file_lock_aquire ();
	bool remove_bool;

	intr_enable ();
	remove_bool =  filesys_remove (file);
	file_lock_release ();
	return remove_bool;
}


int open (const char *file) {
	struct fdesc *fd;
	struct thread *curr = thread_current ();
	bool is_file;

	if (file == NULL) exit(-1);
	if (*file == '\0') return -1;

	fd = malloc (sizeof(struct fdesc));
	if (fd == NULL) return -1;

	file_lock_aquire ();
	intr_enable ();

	void *fp = dir_open_file (curr->curdir, file, &is_file);
	
	file_lock_release ();

	if (fp == NULL) {
		free(fd);
		return -1;
	}

	fd->desc_no = list_entry(list_rbegin (&curr->desc_table), struct fdesc, elem)->desc_no + 1;
	fd->file = fp;
	fd->is_dir = is_file ? false : true;
	list_push_back (&curr->desc_table, &fd->elem);
	
	return fd->desc_no;
}

struct file*
get_file_with_fd (int fd){
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
	if (file == 1 || file == 2) return;
	return (int) file_length (file);
}

int read (int fd, void *buffer, unsigned size) {
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	if (file == 1) return input_getc();
	if (file == 2) return -1;

	if (!ptr_is_writable (buffer)) {
		// printf("buffer is not writable.\n");
		exit(-1);
	}

	file_lock_aquire ();
	intr_enable ();
	int read_ = file_read (file, buffer, size);
	update_dup (file);

	file_lock_release ();
	return read_;
}

int 
write (int fd, const void *buffer, unsigned length) {
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	if(file == 1) return -1;
	if (file == 2) {
		file_lock_aquire ();
		putbuf (buffer, length);
		file_lock_release ();
		return length;		
	}
	
	file_lock_aquire ();

	intr_enable ();
	int writted = (int) file_write (file, buffer, length);
	update_dup (file);

	file_lock_release ();
	return writted;
}

void
seek (int fd, unsigned position) {
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return;
	if (file == 1 || file == 2) return;

	file_lock_aquire ();
	
	file_seek (file, position);
	update_dup (file);

	file_lock_release ();
}

unsigned tell (int fd) {
	struct file* file = get_file_with_fd (fd);
	if (file == NULL) return -1;
	if (file == 1 || file == 2) return -1;

	file_lock_aquire ();
	unsigned pos = file_tell (file);
	file_lock_release ();
	return pos;
}

void close (int fd) {
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
		file_lock_aquire ();
		intr_enable ();
		if (fd_->file > 2) file_close (fd_->file);
		file_lock_release ();
		free (fd_);		
	}
}

int dup2 (int oldfd, int newfd) {
	struct list_elem *i;
	struct thread *curr;
	struct fdesc *oldfdesc = NULL;
	struct fdesc *newfdesc = NULL;
	struct list_elem *pivot;
	struct file* temp;

	curr = thread_current ();
	pivot = list_begin (&curr->desc_table);

	for (i = list_begin (&curr->desc_table); i != list_end (&curr->desc_table); i = list_next (i)) {
		if (list_entry (i, struct fdesc, elem)->desc_no == oldfd) {
			oldfdesc = list_entry (i, struct fdesc, elem);
		}
		if (list_entry (i, struct fdesc, elem)->desc_no == newfd) {
			newfdesc = list_entry (i, struct fdesc, elem);
			pivot = list_next (i);
		}
		else if (list_entry (pivot, struct fdesc, elem)->desc_no < newfd) {
			pivot = list_next (i);
		}
	}
	if (oldfdesc == NULL) return -1;
	if (oldfdesc == newfdesc) return newfd;

	if (oldfdesc->file > 2) temp = file_duplicate (oldfdesc->file);
	else temp = oldfdesc->file;
	if (temp == NULL) goto error;

	file_lock_aquire ();
	if (newfdesc == NULL) {
		newfdesc = malloc (sizeof (struct fdesc));
		if (newfdesc == NULL) goto error;

		newfdesc->desc_no = newfd;
		newfdesc->file = temp;

		list_insert (pivot, &newfdesc->elem);
	}
	else {
		if (temp == NULL) goto error;
		if (newfdesc->file > 2) file_close (newfdesc->file);
		newfdesc->file = temp;
	}

	file_lock_release ();
	return newfdesc->desc_no;

error:
	file_close (temp);
	file_lock_release ();
	return -1;
}

void
update_dup (struct file* file) {
	struct list_elem *i;
	struct thread *curr;
	struct inode *inode;
	struct file *fdfile;
	int pos;

	pos = file_tell (file);
	curr = thread_current ();
	inode = file_get_inode (file);
	
	for (i = list_begin (&curr->desc_table); i != list_end (&curr->desc_table); i = list_next (i)) {
		fdfile = list_entry (i, struct fdesc, elem)->file;
		if (fdfile > 2 && fdfile != file) {
			if (file_get_inode (fdfile) == inode) {
				file_seek (fdfile, pos);
			}
		}
	}
}

/* Do the mmap */
void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	struct thread *cur = thread_current ();
	struct file *file;

	//address and length validity check.
	if (pg_ofs(addr) != 0) return NULL;
	if (addr == 0) return NULL;
	if (is_kernel_vaddr((uint64_t) addr + length) || is_kernel_vaddr((uint64_t) addr)) return NULL;
	if ((uint64_t)addr + length <= (uint64_t) addr) return NULL; 
	for (uint64_t i = addr; i < (addr + length); i = i + PGSIZE) {
		if (spt_find_page (&cur->spt, i) != NULL) return NULL;
	}

	//fd validity check.
	file = get_file_with_fd (fd);
	if (file == NULL) return NULL;
	if (file == 1 || file == 2) return NULL;

	//offset validity check.
	if (offset > file_length (file)) return NULL;
	if (offset % PGSIZE != 0) return NULL;

	file_lock_aquire ();
	intr_enable ();
	void *va = do_mmap (addr, length, writable, file, offset);
	file_lock_release ();
	return va;
}

void 
munmap (void *addr) {
	file_lock_aquire ();
	intr_enable ();
	do_munmap (addr);
	file_lock_release ();
	return;
}