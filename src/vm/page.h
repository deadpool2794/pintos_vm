#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <debug.h>
#include <hash.h>
#include <stdbool.h>
#include <stdint.h>
#include "threads/synch.h"

typedef struct hash sup_page_table_t;

typedef struct sup_page_table_entry
{
  void *page_address;               
  uint64_t access_timestamp;      
  struct hash_elem hash_elem; 
  int swap_location;               
  bool file_origin;             
  struct file *file;          
  int32_t ofs;                
  uint32_t read_bytes;        
  uint32_t zero_bytes;        
  bool can_write;              
  bool is_mmap;               
  struct lock lock;          
} sup_page_table_entry_t;

bool try_fetch_page (void *fault_addr, void *esp);
bool increase_stack_size (void *fault_addr);

sup_page_table_entry_t *new_supplementary_entry (void *page_address, uint64_t access_timestamp);

bool setup_sup_page_table (sup_page_table_t *table);
void free_sup_page_table (sup_page_table_t *table);

unsigned page_hash_func (const struct hash_elem *elem, void *aux UNUSED);
bool page_less_func (const struct hash_elem *a, const struct hash_elem *b,
                     void *aux UNUSED);
sup_page_table_entry_t *sup_table_find (sup_page_table_t *table, void *page);

bool load_from_swap (void *page_address, sup_page_table_entry_t *table_entry);
bool lazy_load (struct file *file, int32_t ofs, uint8_t *upage,
                uint32_t read_bytes, uint32_t zero_bytes, bool can_write,
                bool is_mmap);

bool load_from_file (void *page_address, sup_page_table_entry_t *table_entry);

#endif