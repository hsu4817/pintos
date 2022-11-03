/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
struct list swap_list; /*list for swapping anon pages*/
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	list_init(&swap_list);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	memset (&page->uninit, 0, sizeof(struct uninit_page));

	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;

	/*my implementation*/
	anon_page->page_sec_start = 0;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	struct list_elem *i;
	bool tag = false;
	disk_sector_t disc_sec;

	for(i = list_begin(&swap_list); i != list_end(&swap_list); i = i->next){
		if(list_entry(i->next, struct anon_page, swap_elem_a) == anon_page){
			tag = true;
			break;
		}
	}
	if(tag == false) return false;
	list_remove(&(page->anon.swap_elem_a));

	page->frame->kva = kva;
	
	for(disc_sec = 0; disc_sec < 8; disc_sec++){
		disk_read(swap_disk, page->anon.page_sec_start + disc_sec, page->frame->kva + DISK_SECTOR_SIZE*disc_sec);
	}

	pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, true);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	struct list_elem *i;
	for(i = list_begin(&swap_list); i != list_end(&swap_list); i = i->next){
		if(list_size(&swap_list) == 0){
			list_push_back(&swap_list, &anon_page->swap_elem_a);
			anon_page->page_sec_start = 0;
			break;
		}
		if(i->next == list_end(&swap_list)){
			list_push_back(&swap_list, &anon_page->swap_elem_a);
			anon_page->page_sec_start = list_entry(i, struct anon_page, swap_elem_a)->page_sec_start + 8;
			break;
		}
		if(list_entry(i->next, struct anon_page, swap_elem_a)->page_sec_start - list_entry(i, struct anon_page, swap_elem_a)->page_sec_start == 16){
			list_insert(i->next, &anon_page->swap_elem_a);
			anon_page->page_sec_start = list_entry(i, struct anon_page, swap_elem_a)->page_sec_start + 8;
			break;
		}
	}

	disk_sector_t disc_sec;
	for(disc_sec = 0; disc_sec < 8; disc_sec++){
		disk_write(swap_disk, page->anon.page_sec_start + disc_sec, page->frame->kva + DISK_SECTOR_SIZE*disc_sec);
	}

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	free (page->frame);
	list_remove (&page->elem_cow);
	free (page->cow_layer);

	/*remove from the swap_list if there is*/
	struct list_elem *i;
	for(i = list_begin(&swap_list); i != list_end(&swap_list); i = i->next){
		if(list_entry(i->next, struct anon_page, swap_elem_a) == anon_page){
			list_remove(i);
		}
	}

	return;
}
