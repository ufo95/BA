#ifndef page_table_watch_H
#define page_table_watch_H


#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>
#include "packeranalyser.h"


#define VMI_BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))
#define VMI_GET_BIT(reg, bit) (!!(reg & (1ULL<<bit)))



int add_page_table_watch(drakvuf_t drakvuf, drakvuf_trap_info_t *info, vmi_instance_t vmi);
int custom_taple_trap_cmp(const void* tmp1, const void* tmp2);

#endif