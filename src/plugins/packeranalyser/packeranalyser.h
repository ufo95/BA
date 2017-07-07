#ifndef packeranalyser_H
#define packeranalyser_H

#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>
#include "page_table_watch.h"

enum page_layer {LAYER_PDPT, LAYER_PDT, LAYER_PT, LAYER_2MB};

struct table_trap{
    uint64_t gfn;
    page_layer layer;
    int init;
};

class packeranalyser: public plugin {

    private:

    public:
    	page_mode_t pm;
        int trap=0;
    	int pid=0;
    	drakvuf_trap_t first_cb_trap, ntpvm_cb_trap, ntcontinuecb_trap, thrd_cb_trap;
        GSList *get_address_trap, *execution_cb_trap;
        uint8_t reg_size;
        output_format_t format;
        os_t os;
        const char *r_p;
        GSList *table_traps, *page_write_traps, *page_exec_traps;


        packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output);
        ~packeranalyser();
};

event_response_t page_table_access_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
int pae_walk_from_entry(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, table_trap *entry, uint64_t pa);
int add_page_table_watch(drakvuf_t drakvuf, packeranalyser *p, vmi_instance_t vmi, int init);

struct return_address_data{
    packeranalyser *p;
    addr_t address_pointer;
};


#endif
