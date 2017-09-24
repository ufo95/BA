#ifndef packeranalyser_H
#define packeranalyser_H

#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>
#include "page_table_watch.h"
#include "layers.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
enum page_layer {LAYER_PDPT, LAYER_PDT, LAYER_PT, LAYER_PAGE, LAYER_2MB};

struct table_trap{
    uint64_t gfn;
    page_layer layer;
    int index;
    int init;
};

struct layer_entry{
    GSList *frames = NULL;
    int wrote_from = -1, executed_from = -1;
    
};

struct frame{
    uint64_t gfn;
    drakvuf_trap_t *write_trap;
    drakvuf_trap_t *exec_trap;
};

class packeranalyser: public plugin {

    private:

    public:
    	page_mode_t pm;
        int trap=0, pid=0;
    	drakvuf_trap_t first_cb_trap, ntpvm_cb_trap, ntcontinuecb_trap, thrd_cb_trap;
        GSList *get_address_trap, *execution_cb_trap;
        uint8_t reg_size;
        output_format_t format;
        os_t os;
        const char *r_p;
        GSList *page_write_traps, *page_written_exec_traps, *page_exec_traps;
        GList *table_traps, *layers;

	//int current_exec_layer = -1, current_write_layer = -1;
	int current_exec_layer = 0, number_of_transition=0;
        packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output);
        ~packeranalyser();
};

void print_list_entries(void *item, void *stuff);
event_response_t page_table_access_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t page_exec_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t initial_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
int pae_walk_from_entry(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, table_trap *entry, uint64_t pa);
int add_page_table_watch(drakvuf_t drakvuf, packeranalyser *p, vmi_instance_t vmi, int init);
addr_t p2v(packeranalyser *p, uint64_t pa);

void malloc_test();
void switch_to_layer_with_address(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t pa);
void add_to_first_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t gfn);
void add_to_layer_with_address(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t from_va, uint64_t page_gfn);
void print_layers(packeranalyser *p);
void dump_layer_to_folder(packeranalyser *p, vmi_instance_t vmi, int layer_index);

struct return_address_data{
    packeranalyser *p;
    addr_t address_pointer;
};


#endif
