#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	int donated_priority;				/* Donated priority. */
	int recent_cpu;						/* Recent cpu. */
	int nice;							/* Nice value */
	int64_t sleep;						/* Sleep ticks */
	
	/* Shared between thread.c and synch.c. */
	struct list holding_locks;			/* List of holding locks. */
	struct lock *waiting;				/* Locked with this */
	struct list_elem elem;              /* List element. */
	struct list_elem elem_blocked;		/* List element for blocked list */
	struct list_elem elem_sleep;		/* List element for sleep */

	/*used in process.c and syscall.c*/
	struct thread *parent;				/* Parent process. */
	struct semaphore pwait_sema;		/* Semaphore for process wait. */
	int exit_status;					/* Exit status of thread. default is 0. */
	bool is_kernel;						/* True when the thread is kernel thread. */
	bool someone_is_waiting;			/* Parent called wait. */
	struct thread *pwaiter;				/* Pwaiter process. */
	bool fork_success;					/*fork success 1, fail 0*/
	struct semaphore fork_sema;			/*fork semaphore*/
	struct file *excutable;				/* Exucutable of current process. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
	struct list desc_table;				/* File descripter table. */

#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
	uintptr_t rsp_stack_growth;			/* saved rsp for fault handling. */
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

struct fdesc
{
	int desc_no;
	struct file* file;
	
	struct list_elem elem;
};

struct exit_log_t
{
	tid_t tid;
	tid_t parent_tid;
	int exit_status;

	struct list_elem elem;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;
void blocked_list_init(void);
void blocked_list_remove(struct list_elem *elem_blocked);
void thread_init (void);
void thread_start (void);

void thread_tick (void);
bool is_timer (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_sleep_yield (void);
void thread_yield (void);

void recalc_m_p_downward (void);
void recalc_m_p_upward (void);
int thread_get_modified_priority (struct thread* t);
int thread_get_priority (void);
void thread_set_priority (int);
void thread_set_priority_mlfqs (struct thread* thread_for_set);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
void thread_set_recent_cpu (struct thread* thread_for_set);
void thread_set_recent_all (void);
int thread_get_load_avg (void);
void thread_set_load_avg (void);


bool less_priority(const struct list_elem *a, const struct list_elem *b, void *aux);
void do_iret (struct intr_frame *tf);

struct thread *tid_to_thread (tid_t tid);
struct exit_log_t * seek_exit_log (tid_t tid);
void add_exit_log (struct exit_log_t *new_log);
void set_exit_log (void);
void remove_exit_log (struct exit_log_t *log);

void file_lock_aquire (void);
void file_lock_release (void);
void file_lock_exit (voie);

#endif /* threads/thread.h */
