#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>



event_response_t execution_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    printf("!!!!!!!!!!!!!!!Execution_CB_TRAP!!!!!!!!!!!!!!!!!!!! 0x%" PRIx64 "\n", info->trap_pa);
    return 0;
}

event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {//Page was now written to, so let's see if it gets executed
    packeranalyser *p = (packeranalyser *)info->trap->data;
    /*uint8_t a = 0;
    uint64_t b = 0;*/

    //printf("Write_CB_TRAP 0x%" PRIx64 "\n", info->trap_pa);
    //vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    /*vmi_read_8_pa(vmi, info->trap_pa, &a);

    if (a==0x41){
        vmi_read_64_pa(vmi, info->trap_pa-4, &b);
        printf("0x41:  0x%" PRIx64 " 0x%" PRIx64 "\n", info->trap_pa, b);
    }*/
    /*add_page_table_watch(drakvuf, (packeranalyser *)info->trap->data, vmi, 0);
    drakvuf_release_vmi(drakvuf);*/


    drakvuf_trap_t *new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
    new_trap->memaccess.gfn = info->trap_pa>>12;
    new_trap->memaccess.access = VMI_MEMACCESS_X;
    new_trap->memaccess.type = PRE;
    new_trap->type = MEMACCESS;
    new_trap->cb = execution_cb;
    new_trap->data = p;

    drakvuf_add_trap(drakvuf, new_trap);

    //drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);


    return 0;
}


event_response_t page_table_access_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info){
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    printf("page_table_access_cb!\n");

    add_page_table_watch(drakvuf, (packeranalyser *)info->trap->data, vmi, 0);

    drakvuf_release_vmi(drakvuf);

    return 0;
}

packeranalyser::packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output){
	const struct packeranalyser_config *p = (const struct packeranalyser_config *)config_p;

    this->table_traps = NULL;
    this->page_traps = NULL;

	this->r_p = p->rekall_profile;
	this->pid = p->injected_pid;

	if(!pid || pid < 0){
		printf("packeranalyser: no pid found!\n");
		return;
	}
	printf("[packeranalyser] PID: %i\n", pid);
	
	vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	this->pm = vmi_get_page_mode(vmi, 0);
	drakvuf_release_vmi(drakvuf);

    printf("Page_Mode: ");
    if (this->pm == VMI_PM_LEGACY){
        printf("VMI_PM_LEGACY\n");
    } else if (this->pm == VMI_PM_PAE){
        printf("VMI_PM_PAE\n");
    } else if (this->pm == VMI_PM_IA32E){
        printf("VMI_PM_IA32E\n");
    } else if (this->pm == VMI_PM_UNKNOWN){
        printf("VMI_PM_UNKNOWN\n");
    } else {
        printf("Unknown\n");
    }


    if(vmi_get_address_width(vmi)==8){
        printf("64 bit not yet supporter\n");
        throw -1;
    }

    if(add_page_table_watch(drakvuf, this, vmi, 1)){
        printf("Error add_page_table_watch\n");
    }

}



packeranalyser::~packeranalyser() {
	printf("Goodbye!\n");
}

