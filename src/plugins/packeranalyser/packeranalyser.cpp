#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"


static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
	packeranalyser *p = (packeranalyser*)info->trap->data;
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	reg_t tag = 0, size = 0;
	if(p->pid != (int) vmi_dtb_to_pid (vmi, info->regs->cr3)){
		drakvuf_release_vmi(drakvuf);
		return 0;
	}
    addr_t ret, ret_pa;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    if (p->pm == VMI_PM_IA32E) {
        size = info->regs->rdx;
        tag = info->regs->r8;
    } else {
        ctx.addr = info->regs->rsp+8;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&size) )
            return 0;

        ctx.addr = info->regs->rsp+12;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&tag) )
            return 0;
    }
    


	printf("[%c%c%c%c]:%" PRIu64 "\n",
        ((uint8_t*)&tag)[0],
        ((uint8_t*)&tag)[1],
        ((uint8_t*)&tag)[2],
        ((uint8_t*)&tag)[3],
        (size)
   	);
	drakvuf_release_vmi(drakvuf);
	return 0;
}




packeranalyser::packeranalyser(drakvuf_t drakvuf, const void *config, output_format_t output){
	const struct packeranalyser_config *c = (const struct packeranalyser_config *)config;
	pid = 0;

	pid = c-> injected_pid;

	if(!pid || pid < 0){
		printf("packeranalyser: no pid found!\n");
		return;
	}
	printf("Hellooo! PID: %i\n", pid);
	
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	this->pm = vmi_get_page_mode(vmi, 0);
	drakvuf_release_vmi(drakvuf);

	if (this->pm == VMI_PM_IA32E){
		printf("VMI_PM_IA32E\n");
	}

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