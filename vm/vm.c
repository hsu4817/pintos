/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "string.h"
#include "threads/synch.h"

static struct lock handler_lock;
static struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&handler_lock);
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page, bool writable);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		
		struct page *new_page = malloc(sizeof(struct page));
		if (new_page == NULL) goto err;

		switch VM_TYPE(type) {
			case VM_ANON:
				uninit_new (new_page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new (new_page, upage, init, type, aux, file_backed_initializer);
				break;
		}
		
		struct cow_layer_t *new_cow = malloc(sizeof(struct cow_layer_t));
		if (new_cow == NULL) {
			destroy (new_page);
			free(new_page);
			goto err;
		}
		list_init (&new_cow->pages);
		list_push_back (&new_cow->pages, &new_page->elem_cow);
		new_page->cow_layer = new_cow;
		new_cow->frame = NULL;
		new_page->frame = NULL;

		if (spt_insert_page (spt, new_page)){
			new_page->unit->writable = writable;
			// printf("added %x to pending pg.\n", new_page->va);
			return true;
		}
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct list_elem *i;
	for (i = list_begin (&spt->spt_table); i != list_end(&spt->spt_table); i = list_next(i)) {
		if (va == list_entry (i, struct spt_unit, elem_spt)->page->va) {
			page = list_entry (i, struct spt_unit, elem_spt)->page;
			break;
		}
	}

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct spt_unit *unit;

	struct list_elem *i;
	for (i = list_begin (&spt->spt_table); i != list_end (&spt->spt_table); i = list_next(i)) {
		if (page->va == list_entry (i, struct spt_unit, elem_spt)->page->va) {
			break;
		}
	}
	if (i != list_end (&spt->spt_table)) {
		return false;
	}

	unit = malloc (sizeof(struct spt_unit));
	if (unit != NULL) {
		succ = true;
	}
	else {
		return false;
	}
	unit->page = page;
	unit->is_stack = false;
	unit->mmap_mark = NULL;
	unit->owner = thread_current ();
	page->unit = unit;
	list_push_front (&spt->spt_table, &unit->elem_spt);

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	if (list_empty(&frame_table)) return NULL;
	victim = list_entry (list_begin(&frame_table), struct frame, elem_frame);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	struct list_elem *i;
	/* TODO: swap out the victim and return the evicted frame. */
	if (victim == NULL) return NULL;
	list_remove (&victim->elem_frame);
		
	for (i = list_begin (&victim->cow_layer->pages); i != list_end (&victim->cow_layer->pages); i = list_next(i)) {
		struct page* vpage = list_entry(i, struct page, elem_cow);
		swap_out (vpage);
		vpage->frame = NULL;
		pml4_clear_page (vpage->unit->owner->pml4, vpage->va);
	}
	victim->cow_layer->frame = NULL;
	victim->cow_layer = NULL;

	memset (victim->kva, 0, PGSIZE);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	frame = malloc(sizeof(struct frame));
	frame->kva = palloc_get_page (PAL_USER);
	if (frame->kva == NULL) {
		free (frame);
		frame = vm_evict_frame ();
	}
	frame->cow_layer = NULL;
	list_push_back (&frame_table, &frame->elem_frame);

	ASSERT (frame != NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	struct thread *cur = thread_current ();
	void *va = pg_round_down (addr);
	void *stack_bottom = cur->spt.lowest_stack;

	for (;stack_bottom != va;){
		stack_bottom -= PGSIZE;
		vm_alloc_page (VM_ANON, stack_bottom, true);
		struct page *page = spt_find_page (&cur->spt, stack_bottom);
		vm_do_claim_page (page, true);
		page->unit->is_stack = true;
	}

	cur->spt.lowest_stack = stack_bottom;
	return;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED, struct thread *cur) {
	if (page->unit->writable) {
		printf("%s is trying cow at %x.\n", cur->name, page->va);
		if (list_size(&page->cow_layer->pages)>1){
			struct frame *old_frame = page->frame;
			struct cow_layer_t *new_cow = malloc(sizeof(struct cow_layer_t));
			list_init(&new_cow->pages);
			list_remove(&page->elem_cow);

			list_push_back(&new_cow->pages, &page->elem_cow);
			page->cow_layer = new_cow;
			page->cow_layer->frame = vm_get_frame ();
			page->frame = page->cow_layer->frame;
			
			pml4_clear_page (cur->pml4, page->va);
			pml4_set_page (cur->pml4, page->va, page->frame->kva, true);

			memcpy(page->frame->kva, old_frame->kva, PGSIZE);
			return true;
		}
		else {
			uint64_t *cur_pte = pml4e_walk (cur->pml4, page->va, false);
			ASSERT (cur_pte != NULL);
			*cur_pte = *cur_pte | PTE_W;
			return true;
		}
	}
	else return false;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	bool success = false;
	bool debug = false;
	if (debug) printf("trying handle %x.\n", pg_round_down (addr));

	page = spt_find_page(spt, pg_round_down(addr));
	if (is_kernel_vaddr(addr)) {
		// PANIC("kerneladdr.\n");
		success = false;
	}
	else if (page == NULL) {
		void *rsp = user ? f->rsp : thread_current()->rsp_stack_growth;
		if (addr < rsp - 8) success = false;
		else {
			if ((USER_STACK > addr) && (addr >= USER_STACK - 0x100000)) {
				vm_stack_growth (addr);
				success = true;
			}
			else {
				// PANIC("faild to handle no_spt case.\n");
				success = false;
			}
		}

	}
	else {
		if (not_present){
			success = vm_do_claim_page(page, page->unit->writable);
		}
		else if (!not_present) {
			ASSERT (page->operations->type != VM_UNINIT);
			if (page->unit->writable == false) {
				success = false;
			}
			else {
				PANIC("todo : cow");
				success = vm_handle_wp (page, thread_current ());
			}
		}
		else {
			PANIC("faild to handle spt_exist case.\n");
			success = false;
		}
	}
	if (debug){
		if (!success) {
			printf("failed to handle page fault on %x.\n", addr);
		}
		else {
			printf("successed to handle page fault on %x.\n", addr);
		}
	}

	return success;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL) return false;
	return vm_do_claim_page (page, true);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page, bool writable) {
	struct frame *frame = NULL;
	/* Set links */
	frame = vm_get_frame ();

	page->cow_layer->frame = frame;
	frame->cow_layer = page->cow_layer;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct supplemental_page_table *spt = &thread_current ()->spt;
	pml4_set_page (thread_current ()->pml4, page->va, frame->kva, writable);
	// printf ("mapped %x.\n", page->va);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	list_init(&spt->spt_table);
	spt->owner = thread_current();
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {

	struct list_elem *i;
	struct file *copied_file = NULL;
	list_sort (&src->spt_table, less_func_spt, NULL);


	for (i = list_begin (&src->spt_table); i != list_end (&src->spt_table); i = list_next (i)) {
		struct spt_unit *p_unit = list_entry (i, struct spt_unit, elem_spt);
		struct page *new_page = NULL;

		if (p_unit->page->operations->type == VM_UNINIT) {
			int aux_size = p_unit->page->uninit.type == VM_ANON ? 4 : 3;

			long long int *aux_ = p_unit->page->uninit.aux;
			long long int *new_aux = malloc (sizeof(long long int) * aux_size);
			if (new_aux == NULL) {
				printf ("fail to copy.\n");
				return false;
			}

			if (p_unit->page->uninit.type == VM_ANON) {
				file_lock_aquire ();
				new_aux[0] = file_duplicate (aux_[0]);
				file_lock_release ();			
			}
			else {
				if (p_unit->mmap_mark != NULL) {
					file_lock_aquire ();
					copied_file = file_duplicate (aux_[0]);
					file_lock_release ();
				}
				new_aux[0] = copied_file;
			}
		
			for (int idx = 1; idx < aux_size; idx++) {
				new_aux[idx] = aux_[idx];
			}
			if (vm_alloc_page_with_initializer (p_unit->page->uninit.type, p_unit->page->va, 
				p_unit->writable, p_unit->page->uninit.init, new_aux) == false){
					printf("fail to valloc.\n");
					return false;
				}
			new_page = spt_find_page (dst, p_unit->page->va);

		}
		else if (p_unit->page->operations->type == VM_ANON) {
			if (vm_alloc_page (VM_ANON, p_unit->page->va, p_unit->writable) == false){
				printf("fail to valloc.\n");
				return false;
			}
			new_page = spt_find_page (dst, p_unit->page->va);
			if (vm_do_claim_page (new_page, p_unit->writable) == false){
				printf("fail to init page.\n");
				return false;
			}
			memcpy (new_page->frame->kva, p_unit->page->frame->kva, PGSIZE);
		}
		else if (p_unit->page->operations->type == VM_FILE) {
			if (vm_alloc_page (VM_FILE, p_unit->page->va, p_unit->writable) == false){
				printf("fail to valloc.\n");
				return false;				
			};
			new_page = spt_find_page (dst, p_unit->page->va);
			if (vm_do_claim_page (new_page, p_unit->writable) == false){
				printf("fail to valloc.\n");
				return false;								
			}
			memcpy (new_page->frame->kva, p_unit->page->frame->kva, PGSIZE);

			if (p_unit->mmap_mark != NULL) {
				file_lock_aquire ();
				copied_file = file_duplicate (p_unit->page->file.file);
				file_lock_release ();
			}

			new_page->file.file = copied_file;
			new_page->file.offset = p_unit->page->file.offset;
			new_page->file.size = p_unit->page->file.size;
		}
		else return;

		new_page->unit->is_stack = p_unit->is_stack;
		new_page->unit->writable = p_unit->writable;
		new_page->unit->mmap_mark = p_unit->mmap_mark;
		new_page->unit->mmap_count = p_unit->mmap_count;
		new_page->unit->owner = dst->owner;
	}
	return true;
}


bool less_func_spt (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	if (list_entry(a, struct spt_unit, elem_spt)->page->va < list_entry(b, struct spt_unit, elem_spt)->page->va) return true;
	else return false;
}


/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct list_elem *i;
	struct thread *cur = thread_current ();
	if (cur->is_kernel) return;
	if (list_empty (&spt->spt_table)) return;
	list_sort (&spt->spt_table, less_func_spt, NULL);

	for (i = list_begin(&spt->spt_table); i != list_end(&spt->spt_table);){
		struct spt_unit *cur_unit = list_entry(i, struct spt_unit, elem_spt);
		if (cur_unit->mmap_mark != NULL) {
			file_lock_aquire ();
			intr_enable ();
			do_munmap (cur_unit->mmap_mark);
			file_lock_release ();
			i = list_begin (&spt->spt_table);
			continue;
		}
		i = list_remove(i);
		vm_dealloc_page (cur_unit->page);
		free(cur_unit);
	}
}

void 
munmap_all (void){
	struct list_elem *i;
	struct thread *cur = thread_current ();
	struct supplemental_page_table *spt = &cur->spt;
	if (cur->is_kernel) return;
	if (list_empty (&spt->spt_table)) return;
	
	list_sort (&spt->spt_table, less_func_spt, NULL);

	for (i = list_begin (&spt->spt_table); i != list_end (&spt->spt_table);) {
		struct spt_unit *cur_unit = list_entry (i, struct spt_unit, elem_spt);
		if (cur_unit->mmap_mark != NULL){
			i = list_prev(i);
			do_munmap (cur_unit->mmap_mark);
		}
		i = list_next(i);
	}
}