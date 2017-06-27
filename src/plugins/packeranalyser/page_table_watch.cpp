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
int custom_taple_trap_cmp(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    table_trap *two = (table_trap *)tmp2; 

    if (one->pa == two->pa && one->layer == two->layer){
        return 0;
    } else {
        return 1;
    }
}


static inline uint64_t get_pdptb (uint64_t pdpr){
    return pdpr & VMI_BIT_MASK(5,63);
}
event_response_t page_table_access_cb2(drakvuf_t drakvuf, drakvuf_trap_info_t *info){
    printf("!!!!!!!!Page Table2 accesssed!!!!!!!!!!!!!!!\n");
    return 0;
}

void add_trap(uint64_t pa, packeranalyser *p, drakvuf_t drakvuf, page_layer pl, table_trap *parent){



    drakvuf_trap_t *new_trap;
    int index_parent = -1;
    table_trap *child = (table_trap * )g_malloc0(sizeof(table_trap));
    child->pa = pa;
    child->layer = pl;

    if (g_slist_find_custom(p->table_traps, child, custom_taple_trap_cmp)){//Trap already exsist
        g_free(child);
        return;
    }
    
    
    switch (pl){
        case LAYER_PDPT:
            printf("PDPT");
            break;
        case LAYER_PDT:
            printf("PDT");
            break;
        case LAYER_PT:
            printf("PT");
    }
    printf(": 0x%" PRIx64 "\n", pa);

    printf("Parent: ");
    switch (parent->layer){
        case LAYER_PDPT:
            printf("PDPT");
            break;
        case LAYER_PDT:
            printf("PDT");
            break;
        case LAYER_PT:
            printf("PT");
            break;
        default:
            printf("Huch");
    }
    printf(": 0x%" PRIx64 "\n", parent->pa);



    new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->memaccess.gfn = pa;
    new_trap->memaccess.access = VMI_MEMACCESS_RWX;
    new_trap->memaccess.type = PRE;
    new_trap->name = "page_table_access_cb";
    new_trap->type = MEMACCESS;
    new_trap->cb = page_table_access_cb2;
    new_trap->data = p;



    if(!drakvuf_add_trap(drakvuf, new_trap)){
        printf("Failed to add Trap to: 0x%" PRIx64 "\n", pa);
        return;
    }

    switch (pl){
        case LAYER_PDPT:
            p->table_traps = g_slist_append(p->table_traps, child);
            break;
        case LAYER_PDT:
        case LAYER_PT:
            index_parent = g_slist_position(p->table_traps, g_slist_find_custom(p->table_traps, parent, custom_taple_trap_cmp));
            if (index_parent<0){
                printf("Error parent does not exist\n");
            }
            p->table_traps = g_slist_insert(p->table_traps, child, index_parent);

            break;
        default :
            printf("Huch!\n");
            break;

    }
    printf("Child: \t");
    switch (child->layer){
        case LAYER_PDPT:
            printf("PDPT");
            break;
        case LAYER_PDT:
            printf("PDT");
            break;
        case LAYER_PT:
            printf("PT");
    }
    printf(": 0x%" PRIx64 "\n", child->pa);

    return;
}


int pae_walk(vmi_instance_t vmi, drakvuf_trap_info_t *info, packeranalyser *p, drakvuf_t drakvuf){
    table_trap *parent = (table_trap *)g_malloc0(sizeof(table_trap));
	uint64_t pdpte, pdpte_i, pdt, pdte, pt;
	uint64_t pdpt = get_pdptb(vmi_pid_to_dtb(vmi, p->pid));
	int i = 0;
    printf("pae_walk: %i CR3: 0x%" PRIx64 "\n", p->pid, vmi_pid_to_dtb(vmi, p->pid));

    parent->pa = 0;
    parent->layer = LAYER_PT;

	add_trap(pdpt, p, drakvuf, LAYER_PDPT, parent);//Add trap to the pdpt register


	for (i = 0; i < 4; ++i){//Walk the PDPT
		pdpte_i = pdpt+(i*sizeof(uint64_t));
		vmi_read_64_pa(vmi, pdpte_i, &pdpte);//Read the PDBT i

        /*if (!VMI_GET_BIT(pdpte_i, 0)){
            continue;
        }*/

		pdt = pdpte & VMI_BIT_MASK(12,51);

        parent->pa = pdpt;
        parent->layer = LAYER_PDPT;

		add_trap(pdt, p, drakvuf, LAYER_PDT, parent);//Add trap to the page_directory!

        parent->pa = pdt;
        parent->layer = LAYER_PDT;

        for (int count = 0; count < 512; ++count){
            vmi_read_64_pa(vmi, pdt, &pdte);//Get the Page Directory Table Entry
            if(!VMI_GET_BIT(pdte, 0)){
                pdt+=sizeof(uint64_t);
                continue;
            }

			if (VMI_GET_BIT(pdte, 7)){
                pt = pdte & VMI_BIT_MASK(21, 35);
				printf("2MB-Page: 0x%" PRIx64 "\n", pt);
			} else {
				pt = pdte & VMI_BIT_MASK(12,35);
				add_trap(pt, p, drakvuf, LAYER_PT, parent);//Found a Page Table
			}
        pdt+=sizeof(uint64_t);
		
        }
	}

    g_free(parent);

	return 0;
}

int add_page_table_watch(drakvuf_t drakvuf, drakvuf_trap_info_t *info, vmi_instance_t vmi) {
    printf("add_page_table_watch\n");


    packeranalyser *p = (packeranalyser*)info->trap->data;
    //vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
	page_mode pm = vmi_get_page_mode(vmi, 0);

    printf("after drakvuf_lock_and_get_vmi\n");

    if (pm == VMI_PM_LEGACY){
        
    } else if (pm == VMI_PM_PAE){
        pae_walk(vmi, info, p, drakvuf);
    } else if (pm == VMI_PM_IA32E){
       	
    } else if (pm == VMI_PM_UNKNOWN){
        drakvuf_release_vmi(drakvuf);
        return -1;
    } else {
        drakvuf_release_vmi(drakvuf);
        return -1;
    }
    
    return 0;

}
