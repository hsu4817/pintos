/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "string.h"

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

		if (spt_insert_page (spt, new_page)){
			new_page->unit->uninited = true;
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
	unit->uninited = false;
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

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
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
	frame->cow_layer = NULL;
	if (frame->kva == NULL) {
		PANIC ("todo");
	}

	ASSERT (frame != NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED, struct thread *cur) {
	if (page->unit->writable) {
		if (list_size(&page->cow_layer->pages)>1){
			struct frame *old_frame = page->frame;
			vm_do_claim_page (page, true);
			memcpy(page->frame->kva, old_frame->kva, PGSIZE);
		}
		else {
			uint64_t *cur_pte = pml4e_walk (cur->pml4, page->va, false);
			*cur_pte = *cur_pte | PTE_W;
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

	if (is_kernel_vaddr(addr)) {
		// PANIC("kerneladdr.\n");
		return false;
	}
	page = spt_find_page(spt, pg_round_down(addr));
	if (page == NULL) {
		void *rsp = user ? f->rsp : thread_current()->rsp_stack_growth;
		if (rsp != addr + 8) return false;
		if ((USER_STACK > addr) && (addr > USER_STACK - 0xfffff)) {
			vm_stack_growth (addr);
			return true;
		}
		else {
			// PANIC("faild to handle no_spt case.\n");
			return false;
		}
	}
	else {
		if (page->unit->uninited && not_present){
			page->unit->uninited = false;
			return vm_do_claim_page(page, page->unit->writable);
		}
		else if (!not_present) {
			ASSERT (page->unit->uninited == false);
			return vm_handle_wp (page, thread_current ());
		}
		else {
			// PANIC("faild to handle spt_exist case.\n");
			return false;
		}
	}
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
	if (writable) {
		frame = vm_get_frame ();
		if (list_size(&page->cow_layer->pages) > 1){
			struct cow_layer_t *new_cow = malloc(sizeof(struct cow_layer_t));
			list_remove(&page->elem_cow);

			list_init(&new_cow->pages);
			list_push_back(&new_cow->pages, &page->elem_cow);
			new_cow->frame = frame;
			page->cow_layer = new_cow;
			frame->cow_layer = new_cow;
			page->frame = frame;
		}
		else {
			page->cow_layer->frame = frame;
			page->frame = frame;
			frame->cow_layer = page->cow_layer;
		} 
	}
	else {
		if (page->cow_layer->frame == NULL) {
			frame = vm_get_frame ();
			page->cow_layer->frame = frame;
			frame->cow_layer = page->cow_layer;
			page->frame = frame;
		}
		else {
			page->frame = page->cow_layer->frame;
			frame = page->frame;
		}
	}

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
	for (i = list_begin (&src->spt_table); i != list_end (&src->spt_table); i = list_next (i)) {
		struct spt_unit *c_unit = malloc(sizeof(struct spt_unit));
		struct spt_unit *p_unit = list_entry (i, struct spt_unit, elem_spt);

		c_unit->is_stack = p_unit->is_stack;
		c_unit->uninited = p_unit->uninited;
		c_unit->writable = p_unit->writable;
		c_unit->page = malloc (sizeof(struct page));
		if (c_unit->page == NULL) {
			free(c_unit);
			return false;
		}
		memcpy (c_unit->page, p_unit->page, sizeof(*p_unit->page));
		c_unit->page->unit = c_unit;

		list_push_back(&p_unit->page->cow_layer->pages, &c_unit->page->elem_cow);
		
		if (p_unit->uninited == false) {
			if (!pml4_set_page (thread_current ()->pml4, c_unit->page->va, c_unit->page->frame->kva, false)) {
				free(c_unit->page);
				free(c_unit);
				return false;
			}

			uint64_t *p_pte = pml4e_walk (src->owner->pml4, p_unit->page->va, false);
			if (*p_pte & PTE_W) {
				*p_pte = *p_pte | ~PTE_W;
			}
		}

		list_push_back(&dst->spt_table, &c_unit->elem_spt);
		
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct list_elem *i;
	for (i = list_begin(&spt->spt_table); i != list_end(&spt->spt_table);){
		struct spt_unit *cur_unit = list_entry(i, struct spt_unit, elem_spt);
		i = list_remove(i);
		destroy (cur_unit->page);
		free(cur_unit);
	}
}
