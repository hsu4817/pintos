#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/fat.h"
#include "threads/thread.h"
#include "lib/string.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	cluster_t inode_cluster = 0;
	struct dir *dir = dir_open_root ();
	inode_cluster = fat_create_chain (0);
	inode_sector = cluster_to_sector (inode_cluster);
	bool success = (dir != NULL
			&& inode_cluster != 0
			&& inode_create (inode_sector, initial_size)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_cluster != 0)
		fat_remove_chain (inode_cluster, 0);
	dir_close (dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;
}

bool
filesys_chdir (const char *dir){
	char *_dir = malloc((strlen(dir)+1));
	strlcpy (_dir, dir, strlen(dir)+1);

	char *token, *save_ptr;
	bool success = true;

	struct dir *curr;
	struct inode *curr_inode;

	token = strtok_r (_dir, "/", &save_ptr);

	if(strcmp(token, ".") == 0){
		curr = thread_current()->curdir;
	}
	else if(strcmp(token, "..") == 0){
		curr = thread_current()->curdir;

		success = dir_lookup(curr, token, curr_inode);
		curr = dir_open(curr_inode);

		if(success == false){
			free(_dir);
			return success;
		}
		
	}
	else{
		curr = dir_open_root();
	}

	for (; token != NULL; token = strtok_r (NULL, "/", &save_ptr)){

		success = dir_lookup(curr, token, curr_inode);
		curr = dir_open(curr_inode);

		if(success == false){
			free(_dir);
			return success;
		}
	}
	
	free(_dir);
	return success;
}

bool
filesys_mkdir (const char *dir) {
	char *name = malloc(strlen(dir) + 1);
	strlcpy (name, dir, strlen(dir) + 1);

	char *token, *saveptr;
	struct inode *next_inode;
	struct dir *cur_dir;
	struct dir *next_dir;
	int bytes_parsed = 0;
	int size = strlen (dir);
	cluster_t clst = 0;
	bool success = false;


	token = strtok_r (name, "/", &saveptr);
	if (token == "") {
		cur_dir = dir_open_root ();
	}
	else {
		if (!dir_lookup (thread_current ()->curdir, token, &next_inode)) 
			goto error;
		cur_dir = dir_open (next_inode);
	}
	bytes_parsed += strlen (token) + 1;

	for (;token != NULL; token = strtok_r (NULL, "/", &saveptr)) {
		bytes_parsed += strlen (token) + 1;

		if (!dir_lookup (cur_dir, token, &next_inode)) {
			if (bytes_parsed != size){
				goto error;
			}
			else {
				clst = fat_create_chain(0);
				disk_sector_t dir_sector;
				if (clst == 0) goto error;
				else dir_sector = cluster_to_sector (dir_sector);
				
				if ((strlen(token) <= 14) &&
					dir_create (dir_sector, 2) &&
					dir_add (cur_dir, token, dir_sector)) {
					struct dir *new_dir = dir_open (dir_sector);

					if (dir_add (new_dir, ".", dir_sector) &&
						dir_add (new_dir, "..", next_inode)) {
						success = true;
					}
					else
						goto error;
				}
				else 
					goto error;
			}
		}
		dir_close (cur_dir);
		cur_dir = dir_open (next_inode);
		if (cur_dir == NULL)
			goto error;
	}

	error:
		free (name);
		if (clst != 0) fat_remove_chain (clst, 0);
		success = false;
		return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
