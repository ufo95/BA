#ifndef page_table_watch_H
#define page_table_watch_H


#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>
#include "packeranalyser.h"
#include "layers.h"

#define VMI_BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))
#define VMI_GET_BIT(reg, bit) (!!(reg & (1ULL<<bit)))




int custom_page_write_cmp_address(const void* tmp1, const void* tmp2);
int custom_taple_trap_cmp_withlayer(const void* tmp1, const void* tmp2);
int custom_taple_trap_cmp_gfn(const void* tmp1, const void* tmp2);
int custom_taple_trap_cmp_no_page(const void* tmp1, const void* tmp2);
int custom_page_exec_cmp_gfn(const void* tmp1, const void* tmp2);
#endif