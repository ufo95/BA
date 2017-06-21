#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "page_table_watch.h"
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>
//TODO: MEMORY LEAK!

static inline uint64_t get_pdptb (uint64_t pdpr){
    return pdpr & VMI_BIT_MASK(5,63);
}
void add_trap(uint64_t pa, packeranalyser *p){
	drakvuf_trap_t *new_trap;

	new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->memaccess.gfn = pa;
    new_trap->memaccess.access = VMI_MEMACCESS_W;
    new_trap->memaccess.type = POST;
    new_trap->name = "execution_cb_trap";
    new_trap->type = MEMACCESS;
    new_trap->cb = page_table_access_cb;
    new_trap->data = p;

    return;
}


int pae_walk(vmi_instance_t vmi, drakvuf_trap_info_t *info, packeranalyser *p){
	uint64_t pdpte, pdpte_i, pdt, pdte, pt;
	uint64_t pdpt = get_pdptb(info->regs->cr3);
	int i = 0;

	add_trap(pdpt, p);

	for (i = 0; i < 4; ++i){//Walk the PDPT Registers
		pdpte_i = pdpt+(i*sizeof(uint64_t));
		vmi_read_64_pa(vmi, pdpte_i, &pdpte);//Read the PDBT Register i

		pdt = pdpte & VMI_BIT_MASK(12,51);

		add_trap(pdt, p);

		do {//Walk the Page Directory Table Entries
			vmi_read_64_pa(vmi, pdt, &pdte);//Get the Page Directory Table Entry
			if (VMI_GET_BIT(pdte, 7)){
				printf("2MB\n");
			} else {

				pt = pdte & VMI_BIT_MASK(12,35);

				add_trap(pt, p);//Found a Page Table

				pdte+=sizeof(uint64_t);

			}

		} while (VMI_GET_BIT(pdte, 0));
	}

	return 0;
}

int add_page_table_watch(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    packeranalyser *p = (packeranalyser*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	page_mode pm = vmi_get_page_mode(vmi, 0);

    printf("Page_Mode: ");
    if (pm == VMI_PM_LEGACY){
        
    } else if (pm == VMI_PM_PAE){
        pae_walk(vmi, info, p);
    } else if (pm == VMI_PM_IA32E){
       	
    } else if (pm == VMI_PM_UNKNOWN){
        printf("VMI_PM_UNKNOWN\n");
        drakvuf_release_vmi(drakvuf);
        return -1;
    } else {
        printf("Unknown\n");
        drakvuf_release_vmi(drakvuf);
        return -1;
    }
    


    drakvuf_release_vmi(drakvuf);
    return 0;

}
