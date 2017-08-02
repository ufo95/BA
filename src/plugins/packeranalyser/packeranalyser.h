#ifndef packeranalyser_H
#define packeranalyser_H

#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>
#include "page_table_watch.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define MSR_IA32_DEBUGCTLMSR        0x000001d9
#define IA32_DEBUGCTLMSR_LBR        (1<<0) /* Last Branch Record */
#define IA32_DEBUGCTLMSR_BTF        (1<<1) /* Single Step on Branches */
#define IA32_DEBUGCTLMSR_TR     (1<<6) /* Trace Message Enable */
#define IA32_DEBUGCTLMSR_BTS        (1<<7) /* Branch Trace Store */
#define IA32_DEBUGCTLMSR_BTINT      (1<<8) /* Branch Trace Interrupt */
#define IA32_DEBUGCTLMSR_BTS_OFF_OS (1<<9)  /* BTS off if CPL 0 */
#define IA32_DEBUGCTLMSR_BTS_OFF_USR    (1<<10) /* BTS off if CPL > 0 */
#define IA32_DEBUGCTLMSR_RTM        (1<<15) /* RTM debugging enable */
static inline __attribute__ (( always_inline )) uint64_t
rdmsr ( unsigned int msr ) {
    uint32_t high;
    uint32_t low;

    __asm__ __volatile__ ( "rdmsr" :
                   "=d" ( high ), "=a" ( low ) : "c" ( msr ) );
    return ( ( ( ( uint64_t ) high ) << 32 ) | low );
}
enum page_layer {LAYER_PDPT, LAYER_PDT, LAYER_PT, LAYER_PAGE, LAYER_2MB};

struct table_trap{
    uint64_t gfn;
    page_layer layer;
    int index;
    int init;
};

struct page_exec_trap{
    uint64_t gfn;
    drakvuf_trap_t *trap;
};

class packeranalyser: public plugin {

    private:

    public:
    	page_mode_t pm;
        int trap=0;
    	int pid=0;
        uint64_t last_executed_gfn = 0, current_executed_gfn = 0;
    	drakvuf_trap_t first_cb_trap, ntpvm_cb_trap, ntcontinuecb_trap, thrd_cb_trap;
        GSList *get_address_trap, *execution_cb_trap;
        uint8_t reg_size;
        output_format_t format;
        os_t os;
        const char *r_p;
        GSList *page_write_traps, *page_written_exec_traps, *page_exec_traps;
        GList *table_traps;


        packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output);
        ~packeranalyser();
};
void print_list_entries(void *item, void *stuff);
event_response_t page_table_access_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t page_exec_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);
int pae_walk_from_entry(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, table_trap *entry, uint64_t pa);
int add_page_table_watch(drakvuf_t drakvuf, packeranalyser *p, vmi_instance_t vmi, int init);
addr_t p2v(packeranalyser *p, uint64_t pa);


struct return_address_data{
    packeranalyser *p;
    addr_t address_pointer;
};


#endif
