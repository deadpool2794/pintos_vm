#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <debug.h>
#include <stdint.h>
#include <list.h>
#include "vm/page.h"
#include "threads/thread.h"

typedef struct frame_table_entry
{
  void *frame_location;                        /* Address of frame */
  tid_t holder;                             /* Owner of the frame */
  sup_page_table_entry_t *supplementary_entry; /* Corresponding sup table entry */
  struct list_elem elem;                   /* List elem in frame table */
} frame_table_entry_t;

frame_table_entry_t *allocate_frame_entry (void *frame_location, tid_t holder,
                                            sup_page_table_entry_t *sup_entry);

frame_table_entry_t *create_new_frame (sup_page_table_entry_t *sup_entry);

void release_frame (void *frame_location);

typedef bool (*frame_table_action_cmp) (frame_table_entry_t *, void *);
typedef bool (*frame_table_action_func) (frame_table_entry_t *);
void process_frame_table_if (frame_table_action_cmp if_cmp, void *cmp_val,
                             frame_table_action_func action_func);
bool frame_table_entry_crspd_frame (frame_table_entry_t *entry,
                                    void *frame_location);
void frame_table_init (void);
frame_table_entry_t *displace_one_frame (void);

bool frame_access_time_less (const struct list_elem *,
                             const struct list_elem *, void *aux UNUSED);
#endif