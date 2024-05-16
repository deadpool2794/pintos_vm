#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include <string.h>

extern struct lock filesys_lock;
extern bool install_page (void *, void *, bool);

sup_page_table_entry_t *
new_supplementary_entry (void *page_address, uint64_t access_timestamp)
{
  sup_page_table_entry_t *entry
      = (sup_page_table_entry_t *)malloc (sizeof (sup_page_table_entry_t));

  if (!entry)
    return NULL;
  entry->page_address = pg_round_down (page_address);
  entry->access_timestamp = access_timestamp;
  entry->swap_location = SWAP_NOT_ASSIGNED;
  entry->file_origin = false;
  entry->file = NULL;
  entry->ofs = 0;
  entry->read_bytes = 0;
  entry->zero_bytes = 0;
  entry->can_write = false;
  entry->is_mmap = false;
  lock_init (&entry->lock);
  return entry;
}

bool
setup_sup_page_table (sup_page_table_t *table)
{
  return hash_init (table, page_hash_func, page_less_func, NULL);
}

static void
do_supplementary_entry_free (struct hash_elem *e, void *aux UNUSED)
{
  sup_page_table_entry_t *entry
      = hash_entry (e, sup_page_table_entry_t, hash_elem);
  /* Release corresponding swap space when necessary */
  if (entry->swap_location != SWAP_NOT_ASSIGNED)
    release_swap (entry->swap_location);
  free (entry);
}

void
free_sup_page_table (sup_page_table_t *table)
{
  hash_destroy (table, do_supplementary_entry_free);
}

unsigned
page_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const sup_page_table_entry_t *entry
      = hash_entry (elem, sup_page_table_entry_t, hash_elem);
  return hash_bytes (&entry->page_address, sizeof (entry->page_address));
}

bool
page_less_func (const struct hash_elem *a, const struct hash_elem *b,
                void *aux UNUSED)
{
  const sup_page_table_entry_t *entry_a
      = hash_entry (a, sup_page_table_entry_t, hash_elem);
  const sup_page_table_entry_t *entry_b
      = hash_entry (b, sup_page_table_entry_t, hash_elem);
  return (uint32_t)entry_a->page_address < (uint32_t)entry_b->page_address;
}

sup_page_table_entry_t *
sup_table_find (sup_page_table_t *table, void *page)
{
  if (!table || !page)
    return NULL;
  sup_page_table_entry_t entry;
  entry.page_address = pg_round_down (page);
  struct hash_elem *found = hash_find (table, &entry.hash_elem);
  if (!found)
    return NULL;
  return hash_entry (found, sup_page_table_entry_t, hash_elem);
}

bool
try_fetch_page (void *fault_addr, void *esp)
{
  struct thread *cur = thread_current ();
  sup_page_table_entry_t *sup_entry
      = sup_table_find (&cur->sup_page_table, fault_addr);
  if (!sup_entry)
    {
      if ((uint32_t)fault_addr < (uint32_t)esp - 32)
        return false;
      return increase_stack_size (fault_addr);
    }
  else if (sup_entry->file_origin)
    {
      return load_from_file (fault_addr, sup_entry);
    }
  else
    {
      return load_from_swap (fault_addr, sup_entry);
    }
}

bool
increase_stack_size (void *fault_addr)
{
  struct thread *cur = thread_current ();
  sup_page_table_entry_t *table_entry
      = new_supplementary_entry (fault_addr, timer_ticks ());
  if (!table_entry)
    return false;

  frame_table_entry_t *frame_entry = create_new_frame (table_entry);
  if (!frame_entry)
    {
      free (table_entry);
      return false;
    }
  void *k_page = frame_entry->frame_location;
  bool success
      = install_page (table_entry->page_address, k_page, true)
        && !hash_insert (&cur->sup_page_table, &table_entry->hash_elem);
  if (!success)
    {
      free (table_entry);
      release_frame (k_page);
      return false;
    }
  return true;
}

bool
load_from_swap (void *page_address, sup_page_table_entry_t *table_entry)
{
  frame_table_entry_t *frame = create_new_frame (table_entry);
  lock_acquire (&table_entry->lock);
  read_frame_from_storage (frame, table_entry->swap_location);
  table_entry->swap_location = SWAP_NOT_ASSIGNED;
  table_entry->access_timestamp = timer_ticks ();
  bool success = install_page (table_entry->page_address, frame->frame_location,
                               table_entry->can_write);
  if (!success)
    {
      release_frame (frame->frame_location);
      hash_delete (&thread_current ()->sup_page_table,
                   &table_entry->hash_elem);
      lock_release (&table_entry->lock);
      return false;
    }
  lock_release (&table_entry->lock);
  return true;
}

bool
lazy_load (struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes,
           uint32_t zero_bytes, bool can_write, bool is_mmap)
{
  int32_t offset = ofs;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      sup_page_table_entry_t *sup_entry
          = new_supplementary_entry (upage, timer_ticks ());
      if (!sup_entry)
        return false;
      sup_entry->file_origin = true;
      sup_entry->file = file;
      sup_entry->read_bytes = page_read_bytes;
      sup_entry->zero_bytes = page_zero_bytes;
      sup_entry->can_write = can_write;
      sup_entry->ofs = offset;
      sup_entry->is_mmap = is_mmap;

      struct thread *cur = thread_current ();
      if (hash_insert (&cur->sup_page_table, &sup_entry->hash_elem))
        {
          free (sup_entry);
          return false;
        }

      offset += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

bool
load_from_file (void *page_address, sup_page_table_entry_t *table_entry)
{
  frame_table_entry_t *frame_entry = create_new_frame (table_entry);
  if (!frame_entry)
    return false;
  lock_acquire (&table_entry->lock);
  void *kernel_page = frame_entry->frame_location;
  lock_acquire (&filesys_lock);
  file_seek (table_entry->file, table_entry->ofs);
  if (file_read (table_entry->file, kernel_page, table_entry->read_bytes)
      != (int)table_entry->read_bytes)
    {
      release_frame (kernel_page);
      lock_release (&filesys_lock);
      lock_release (&table_entry->lock);
      return false;
    }
  lock_release (&filesys_lock);
  memset (kernel_page + table_entry->read_bytes, 0, table_entry->zero_bytes);
  if (!install_page (table_entry->page_address, kernel_page, table_entry->can_write))
    {
      release_frame (kernel_page);
      lock_release (&table_entry->lock);
      return false;
    }
  lock_release (&table_entry->lock);
  return true;
}