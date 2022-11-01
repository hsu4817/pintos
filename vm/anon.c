/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

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
struct list *swap_list; /*list for swapping anon pages*/
disk_sector_t disk_sec; /*overall disk_sec*/
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	swap_list = malloc(sizeof(struct list));
	list_init(swap_list);
	disk_sec = 0;
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	memset (&page->uninit, 0, sizeof(struct anon_page));
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;

	/*my implementation*/
	list_push_back(swap_list, &anon_page->swap_elem_a);
	anon_page->page_sec_start = disk_sec;
	disk_sec = disk_sec + 8;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	struct list_elem *i;
	bool tag = false;
	for(i = list_begin(swap_list); i != list_end(swap_list); i = i->next){
		if(i == anon_page) tag = true;
	}
	if(tag == false) return false;

	page->frame->kva = kva;
	

	//이게 맞나? 고민됨
	disk_sector_t disc_sec;
	for(disc_sec = 0; disc_sec < 8; disc_sec++){
		disk_read(swap_disk, page->anon.page_sec_start + disc_sec, page->frame->kva + DISK_SECTOR_SIZE*disc_sec);
	}
	list_remove(&(page->anon.swap_elem_a));

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	struct list_elem *i;
	bool tag = false;
	for(i = list_begin(swap_list); i != list_end(swap_list); i = i->next){
		if(i == anon_page) tag = true;
	}
	if(tag == false) return false;

	disk_sector_t disc_sec;
	for(disc_sec = 0; disc_sec < 8; disc_sec++){
		disk_write(swap_disk, page->anon.page_sec_start + disc_sec, page->frame->kva + DISK_SECTOR_SIZE*disc_sec);
	}
	list_remove(&(page->anon.swap_elem_a));

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	/*remove from the swap_list if there is*/
	struct list_elem *i;
	for(i = list_begin(swap_list); i != list_end(swap_list); i = i->next){
		if(i == anon_page){
			list_remove(i);
		}
	}

	return;
}
