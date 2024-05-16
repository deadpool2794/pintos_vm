#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include <bitmap.h>

static struct bitmap *swap_table;
static struct lock swap_table_lock;
static struct block *global_swap_block;

bool
setup_swap_space ()
{
  global_swap_block = block_get_role (BLOCK_SWAP);
  swap_table = bitmap_create (block_size (global_swap_block));
  if (!swap_table)
    return false;
  lock_init (&swap_table_lock);
  return true;
}

void
cleanup_swap_space ()
{
  bitmap_destroy (swap_table);
}

void
release_swap (int sector_idx)
{
  lock_acquire (&swap_table_lock);
  bitmap_set_multiple (swap_table, sector_idx, 8, false);
  lock_release (&swap_table_lock);
}

void
read_frame_from_storage (frame_table_entry_t *frame, int sector_idx)
{
  for (int i = 0; i < 8; ++i)
    {
      block_read (global_swap_block, sector_idx + i,
                  frame->frame_location + (i * BLOCK_SECTOR_SIZE));
    }
  release_swap (sector_idx);
}

void
write_frame_to_storage (frame_table_entry_t *frame)
{
  int sector_idx = fetch_new_swap_space ();
  frame->supplementary_entry->swap_location = sector_idx;
  for (int i = 0; i < 8; ++i)
    {
      block_write (global_swap_block, sector_idx + i,
                   frame->frame_location + (i * BLOCK_SECTOR_SIZE));
    }
}

int
fetch_new_swap_space ()
{
  lock_acquire (&swap_table_lock);
  size_t sector = bitmap_scan_and_flip (swap_table, 0, 8, false);
  if (sector == BITMAP_ERROR)
    syscall_exit (-1);
  lock_release (&swap_table_lock);
  return sector;
}
