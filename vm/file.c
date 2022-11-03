/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool lazy_load_file (struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	memset (&page->uninit, 0, sizeof(struct uninit_page));

	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	free (page->frame);
	list_remove (&page->elem_cow);
	free (page->cow_layer);
	return;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	//allocate pages.
	unsigned long read_bytes = length;
	void *upage = addr;
	struct page *first = NULL;

	int prev_pagecnt = 0;
	while (read_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;

		long long int *aux = (long long int*) malloc (sizeof(long long int) * 3);
		aux[0] = (long long int) file_duplicate (file);
		aux[1] = (long long int) offset + (PGSIZE * prev_pagecnt);
		aux[2] = (long long int) page_read_bytes;

		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_file, aux)){
			return NULL;
		}

		if (addr == upage) {
			first = spt_find_page (&thread_current ()->spt, addr);
			ASSERT (first != NULL);
			first->unit->mmap_mark = addr;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		upage += PGSIZE;
		prev_pagecnt++;
	}
	first->unit->mmap_count = prev_pagecnt;
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread *cur = thread_current ();
	struct page *upage = spt_find_page (&cur->spt, addr);
	struct file *file;
	int pgcnt;

	if (upage == NULL) return;
	if (upage->unit->mmap_mark != addr) {
		// printf("some error.\n");
		return;
	}

	pgcnt = upage->unit->mmap_count;
	
	for (int i = 0; i < pgcnt; i++) {
		ASSERT (upage != NULL);
		// printf("unmap %x ",upage->va);
		if (upage->operations->type == VM_UNINIT) {
			// printf("type of uninit.\n");
			struct spt_unit *unit = upage->unit;
			long long int *aux_ = upage->uninit.aux; 
			file_close (aux_[0]);
			vm_dealloc_page (upage);
			list_remove (&unit->elem_spt);
			free (unit);
		}
		else if (upage->operations->type == VM_FILE) {
			// printf("type of file.\n");
			uint64_t *pte = pml4e_walk (cur->pml4, upage->va, false);
			if (pte != NULL) {
				if (*pte & PTE_D) {
					file_write_at (upage->file.file, upage->frame->kva, upage->file.size, upage->file.offset);
				}
			}
			file_close (upage->file.file);
			pml4_clear_page (&cur->pml4, upage->va);
			struct spt_unit *unit = upage->unit;
			list_remove (&unit->elem_spt);
			vm_dealloc_page (upage);
			free (unit);
		}

		addr += PGSIZE;
		upage = spt_find_page (&cur->spt, addr);
	}
}

static bool
lazy_load_file (struct page *page, void *aux) {
	long long int *aux_ = aux;
	struct file *file = aux_[0];
	off_t ofs = aux_[1];
	uint32_t page_read_bytes = aux_[2];

	off_t old_pos = file_tell (file);
	file_seek (file, ofs);
	off_t actual_read = file_read (file, page->frame->kva, page_read_bytes);
	
	memset (page->frame->kva + actual_read, 0, PGSIZE - actual_read);
	page->file.file = file;
	page->file.offset = ofs;
	page->file.size = actual_read;
	free (aux);
	file_seek (file, old_pos);

	return true;
}