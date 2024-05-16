#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include "vm/frame.h"

#define SWAP_NOT_ASSIGNED (-1)

bool setup_swap_space (void);
void cleanup_swap_space (void);
void release_swap (int sector_idx);
void read_frame_from_storage (frame_table_entry_t *frame, int sector_idx);
void write_frame_to_storage (frame_table_entry_t *frame);
int fetch_new_swap_space (void);

#endif
