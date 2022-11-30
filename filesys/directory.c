#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/fat.h"
#include "lib/string.h"
#include "threads/thread.h"

/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry), DIR);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
	return dir_open (inode_open (cluster_to_sector (ROOT_DIR_CLUSTER)));
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (!lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	if (inode_is_dir(inode)) {
		if (inode_get_opencnt (inode) > 1) 
			goto done;
	}


	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			if (strcmp (e.name, ".") && strcmp (e.name, "..")) {
				strlcpy (name, e.name, NAME_MAX + 1);
				return true;
			}
		}
	}
	return false;
}

/* Walk through dir TARGET. Stores parent directory of target to PDIR, 
 * and stores inode of target to INODE if EXIST is true. */
bool
dir_walk (const char *target, struct dir **pdir, struct inode **inode, char *file_name, 
			bool exist, struct dir *idir) {	
	char *path = malloc (strlen(target)+1);
	strlcpy (path, target, strlen(target)+1);

	char *token, *saveptr;
	struct inode *next_inode = NULL;
	struct dir *cur_dir = NULL;
	int bytes_parsed = 0;
	int size = strlen (target);
	bool success = false;

	// printf ("dir walk | tokenize %s\n", path);

	token = path;
	saveptr = path;
	while (*saveptr == '/') 
		saveptr++;
		bytes_parsed++;

	if (saveptr > path) {
		/* absolute path */
		if (saveptr - path == 1)
			cur_dir = dir_open_root ();
		else 
			goto done;
	}
	else 
		/* relative path */
		cur_dir = idir;
		if (cur_dir)
			cur_dir = dir_reopen(cur_dir);
		else
			cur_dir = dir_open_root ();
	
	if (cur_dir == NULL)
		goto done;

	token = saveptr;

	while (saveptr < path + size) {
		while (*saveptr != '/' && *saveptr != '\0') {
			saveptr++;
			bytes_parsed++;
		}
		if (token == saveptr)
			goto done;
		*saveptr = '\0';
		if (saveptr - token > 14)
			goto done;

		if (saveptr == path + size) {
			// printf ("dir walk | goal is %s\n", token);
			dir_lookup (cur_dir, token, &next_inode);
			if (exist && next_inode) {
				if (inode_get_type (next_inode) == LINK) {
					success = dir_symlink_resolve (&cur_dir, &next_inode);
				}
				else
					success = true;
			}
			else if (!exist && (next_inode == NULL)) {
				success = true;
			}
			goto done;
		}
		else {
			if (!dir_lookup (cur_dir, token, &next_inode)) {
				goto done;
			}
		}

		if (inode_get_type (next_inode) == LINK) {
			if (!dir_symlink_resolve (&cur_dir, &next_inode))
				goto done;
		}
		if (!inode_is_dir (next_inode))
			goto done;
		
		dir_close (cur_dir);
		cur_dir = dir_open (next_inode);
		if (cur_dir == NULL)
			goto done;
		token = ++saveptr;
	}

	PANIC ("dir walk | must not reach");
	done:
		if (success) {
			// printf ("dir walk | walk success. data copying...\n");
			if (inode) *inode = next_inode;
			else if (exist) inode_close (next_inode);
			if (pdir) *pdir = cur_dir;
			else dir_close (cur_dir);
			if (file_name) memcpy (file_name, token, strlen(token) + 1);
			// printf("dir walk | return %s\n", token);
		}
		else {
			// printf ("dir walk | walk fail.\n");
			dir_close(cur_dir);
			inode_close (next_inode);
		}
		free (path);
		return success;
}

/* Check if DIR is empty. (has only "." and "..") */
bool
dir_is_empty (struct dir *dir) {
	struct dir_entry e;
	size_t ofs;
	int cnt;

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e) {
		if (e.in_use) {
			if (strcmp (e.name, ".") && strcmp (e.name, ".."))
				return false;
		}
	}
	return true;
}

int
dir_create_symlink (const char *target, const char *linkpath){
	struct dir *dir;
	char name[15];
	if (!dir_walk (linkpath, &dir, NULL, name, false, thread_current ()->curdir))
		return -1;
	
	cluster_t clst = fat_create_chain (0);
	off_t size = strlen (target) + 1;
	struct inode *inode;
	bool success = false;
	if (clst == 0)
		return false;
	
	if (inode_create (cluster_to_sector (clst), size, LINK)){
		inode = inode_open (cluster_to_sector (clst));
		inode_write_at (inode, target, size, 0);
		success = dir_add (dir, name, cluster_to_sector (clst));
		if (!success) 
			inode_remove (inode);
		inode_close (inode);
		return success;
	}
	else {
		fat_remove_chain (clst, 0);
		return false;
	}
}

bool
dir_symlink_resolve (struct dir **dir, struct inode **inode) {
	struct inode *link = *inode;
	size_t path_length = inode_length (link);
	char *path = malloc (path_length);
	inode_read_at (link, path, path_length, 0);

	bool success = dir_walk (path, dir, inode, NULL, true, *dir);
	free(path);
	return success;
}