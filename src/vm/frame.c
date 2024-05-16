#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"

extern struct lock filesys_lock;

static struct list frame_table;
static struct lock frame_table_lock;

frame_table_entry_t *
allocate_frame_entry (void *frame_location, tid_t holder,
                       sup_page_table_entry_t *sup_entry)
{
  frame_table_entry_t *entry
      = (frame_table_entry_t *)malloc (sizeof (frame_table_entry_t));

  if (!entry)
    return NULL;
  entry->frame_location = frame_location;
  entry->holder = holder;
  entry->supplementary_entry = sup_entry;
  return entry;
}

frame_table_entry_t *
create_new_frame (sup_page_table_entry_t *sup_entry)
{
  if (!sup_entry)
    return NULL;

  void *k_page = palloc_get_page (PAL_USER);
  frame_table_entry_t *frame_entry;
  if (!k_page)
    {
      lock_acquire (&sup_entry->lock);
      frame_entry = displace_one_frame ();
      frame_entry->holder = thread_tid ();
      frame_entry->supplementary_entry = sup_entry;
      lock_release (&sup_entry->lock);
      return frame_entry;
    }
  frame_entry = allocate_frame_entry (k_page, thread_tid (), sup_entry);
  if (!frame_entry)
    {
      palloc_free_page (k_page);
      return NULL;
    }
  lock_acquire (&frame_table_lock);
  list_ins_back (&frame_table, &frame_entry->elem);
  lock_release (&frame_table_lock);
  return frame_entry;
}

static bool
free_frame_table_entry (frame_table_entry_t *frame_entry)
{
  list_remove (&frame_entry->elem);
  palloc_free_page (frame_entry->frame_location);
  free (frame_entry);
  return true;
}

void
release_frame (void *frame_location)
{
  if (!frame_location)
    return;
  process_frame_table_if (frame_table_entry_crspd_frame, frame_location,
                          free_frame_table_entry);
}

void
process_frame_table_if (frame_table_action_cmp if_cmp, void *cmp_val,
                        frame_table_action_func action_func)
{
  lock_acquire (&frame_table_lock);
  for (struct list_elem *e = list_begin (&frame_table), *next;
       e != list_end (&frame_table); e = next)
    {
      next = list_next (e);
      frame_table_entry_t *entry = list_entry (e, frame_table_entry_t, elem);
      if (if_cmp (entry, cmp_val) && action_func (entry))
        {
          break;
        }
    }
  lock_release (&frame_table_lock);
}

bool
frame_table_entry_crspd_frame (frame_table_entry_t *entry, void *frame_location)
{
  return entry->frame_location == frame_location;
}

void
frame_table_init ()
{
  list_init (&frame_table);
  lock_init (&frame_table_lock);
}

frame_table_entry_t *
displace_one_frame ()
{
  struct list_elem *min_elem
      = list_min (&frame_table, frame_access_time_less, NULL);
  frame_table_entry_t *frame
      = list_entry (min_elem, frame_table_entry_t, elem);

  lock_acquire (&frame_table_lock);
  struct thread *cur = thread_current ();
  if (frame->supplementary_entry->file_origin && frame->supplementary_entry->is_mmap
      && pagedir_is_dirty (cur->pagedir, frame->supplementary_entry->page_address))
    {
      lock_acquire (&filesys_lock);
      file_seek (frame->supplementary_entry->file, frame->supplementary_entry->ofs);
      file_write (frame->supplementary_entry->file, frame->supplementary_entry->page_address,
                  frame->supplementary_entry->read_bytes);
      lock_release (&filesys_lock);
    }
  else
    {
      frame->supplementary_entry->file_origin = false;
      write_frame_to_storage (frame);
    }
  pagedir_clear_page (get_thread (frame->holder)->pagedir,
                      frame->supplementary_entry->page_address);
  lock_release (&frame_table_lock);
  return frame;
}

bool
frame_access_time_less (const struct list_elem *a, const struct list_elem *b,
                        void *aux UNUSED)
{
  frame_table_entry_t *frame_a = list_entry (a, frame_table_entry_t, elem);
  frame_table_entry_t *frame_b = list_entry (b, frame_table_entry_t, elem);
  sup_page_table_entry_t *page_a = frame_a->supplementary_entry;
  sup_page_table_entry_t *page_b = frame_b->supplementary_entry;
  bool less_than = page_a->access_timestamp < page_b->access_timestamp;
  if (page_a->can_write != page_b->can_write)
    {
      return page_a->can_write;
    }
  if (is_kernel_vaddr (page_a->page_address) != is_kernel_vaddr (page_b->page_address))
    return !is_kernel_vaddr (page_a->page_address);
  return less_than;
}