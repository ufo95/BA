#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"


static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
	printf("HUHUHU\n");
	return 0;
}




packeranalyser::packeranalyser(drakvuf_t drakvuf, const void *config, output_format_t output){
	int pid = 0;
	const struct packeranalyser_config *c = (const struct packeranalyser_config *)config;

	pid = c-> injected_pid;

	if(!pid || pid < 0){
		printf("packeranalyser: no pid found!\n");
		return;
	}
	printf("Hellooo! PID: %i\n", pid);
	
	this->poolalloc.breakpoint.lookup_type = LOOKUP_PID;
    this->poolalloc.breakpoint.pid = 4;
    this->poolalloc.breakpoint.addr_type = ADDR_RVA;
    this->poolalloc.breakpoint.module = "ntoskrnl.exe";
    this->poolalloc.name = "ExAllocatePoolWithTag";
    this->poolalloc.type = BREAKPOINT;
    this->poolalloc.cb = cb;
    this->poolalloc.data = (void*)this;


    if ( !drakvuf_get_function_rva(c->rekall_profile, "ExAllocatePoolWithTag", &this->poolalloc.breakpoint.rva) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->poolalloc) )
        throw -1;
}



packeranalyser::~packeranalyser() {
	printf("Goodbye!\n");
}