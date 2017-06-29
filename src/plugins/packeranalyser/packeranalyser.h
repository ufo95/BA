#ifndef packeranalyser_H
#define packeranalyser_H

#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>
#include "page_table_watch.h"


#define VMI_BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))



class packeranalyser: public plugin {

    private:

    public:
    	page_mode_t pm;
        int trap=0;
    	int pid=0;
    	drakvuf_trap_t ntcontinuecb_trap;
        GSList *get_address_trap, *execution_cb_trap;
        uint8_t reg_size;
        output_format_t format;
        os_t os;
        const char *r_p;
        GSList *table_traps, *page_traps;

        packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output);
        ~packeranalyser();
};

event_response_t page_table_access_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);

enum page_layer {LAYER_PDPT, LAYER_PDT, LAYER_PT, LAYER_2MB};

struct return_address_data{
    packeranalyser *p;
    addr_t address_pointer;
};

struct table_trap{
    uint64_t pa;
    page_layer layer;
    int init;
};



#endif
