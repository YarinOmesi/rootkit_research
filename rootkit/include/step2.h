#ifndef YARIN_MODULE_STEP2_H
#define YARIN_MODULE_STEP2_H
#include <linux/types.h>

ssize_t step2_hide_pid(char* read_block_id, char* read_path, char* read_buffer, size_t read_buffer_size, int port_to_hide);

#endif //YARIN_MODULE_STEP2_H
