#ifndef YARIN_MODULE_STEP1_H
#define YARIN_MODULE_STEP1_H
#include <linux/types.h>

unsigned long step1_hide_file_by_name(void* getdents_buffer, size_t getdents_buffer_size, char* filename_to_hide);

#endif //YARIN_MODULE_STEP1_H
