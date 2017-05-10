#ifndef packeranalyser_H
#define packeranalyser_H

#include <glib.h>
#include "plugins/plugins.h"
#include "plugins/private.h"

class packeranalyser: public plugin {

    private:
        GSList *traps;

    public:
    	page_mode_t pm;
    	int pid;
    	drakvuf_trap_t poolalloc;
        uint8_t reg_size;
        output_format_t format;
        os_t os;
        packeranalyser(drakvuf_t drakvuf, const void *config, output_format_t output);
        ~packeranalyser();
};

#endif
