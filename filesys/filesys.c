#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/fat.h"

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
	struct dir *dir = dir_open_root ();
	if (!dir_add (dir, ".", cluster_to_sector (ROOT_DIR_CLUSTER)))
		PANIC ("root directory creation fail");
	dir_close (dir);

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
	bool success = false;

	struct dir *dir = dir_open_root ();
	inode_cluster = fat_create_chain (0);
	if (inode_cluster) {
		if (inode_create (cluster_to_sector (inode_cluster), initial_size, false)) {
			success = dir_add (dir, name, cluster_to_sector (inode_cluster));
		}
	} 
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
	struct dir *dir = NULL;
	struct inode *inode = NULL;

	if (strcmp(name, "/")) {
		if (!dir_walk (name, &dir, &inode, NULL, true)) {
			return false;
		}
	}
	else
		return dir_open_root ();

	dir_close (dir);
	if (inode_is_dir (inode)) 
		return dir_open (inode);
	else
		return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	struct dir *dir = NULL;
	struct inode *inode = NULL;
	char file_name[15];
	bool success = false;

	if (strcmp(name, "/")){
		if (!dir_walk (name, &dir, &inode, file_name, true)) {
			return false;
		}
	}
	else
		return false;

	if (inode_is_dir (inode)) {
		struct dir *target_dir = dir_open (inode);
		if (!dir_is_empty (target_dir))
			success = false;
		dir_close (target_dir);
	}

	success = dir_remove (dir, file_name);
	dir_close (dir);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	
	if (!dir_create (cluster_to_sector (ROOT_DIR_CLUSTER), 16))
		PANIC ("root directory creation failed");

	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
