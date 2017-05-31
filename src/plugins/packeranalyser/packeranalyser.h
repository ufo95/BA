#ifndef packeranalyser_H
#define packeranalyser_H

#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"
#include <libdrakvuf/libdrakvuf.h>

class packeranalyser: public plugin {

    private:
    public:
        GList *exec_address_list=NULL;
    	page_mode_t pm;
        int trap=0;
    	int pid=0;
    	drakvuf_trap_t first_cb_trap, ntpvm_cb_trap, ntcontinuecb_trap, thrd_cb_trap;
        uint8_t reg_size;
        output_format_t format;
        os_t os;
        const char *r_p;
        packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output);
        ~packeranalyser();
};

#endif
