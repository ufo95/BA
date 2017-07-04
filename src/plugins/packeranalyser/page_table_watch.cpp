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

static inline uint64_t get_pdptb (uint64_t pdpr){
    return pdpr & VMI_BIT_MASK(5,63);
}

int custom_taple_trap_cmp_address(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    uint64_t *two = (uint64_t *)tmp2;

    if ((uint64_t)one->pa==*two){
        return 0;
    } else {
        return 1;
    }
}

int custom_taple_trap_cmp_withlayer(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    table_trap *two = (table_trap *)tmp2; 

    if (one->pa == two->pa && one->layer == two->layer){
        return 0;
    } else {
        return 1;
    }
}
void add_page_watch_pae(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t page_table_address){
    drakvuf_trap_t *new_trap = NULL;
    uint64_t *page_address = NULL;
    uint64_t pte_address = 0;
    uint64_t pte = 0;


    //printf("PTA: 0x%" PRIx64 " ", page_table_address);

    for (int i = 0; i < 512; ++i){
        page_address = (uint64_t *)g_malloc0(sizeof(uint64_t));
        pte_address = page_table_address+i*sizeof(uint64_t);

        vmi_read_64_pa(vmi, pte_address, &pte);//Get the Page Table Entry
        if(!VMI_GET_BIT(pte, 0)){
            continue;
        }

        *page_address = (pte & VMI_BIT_MASK(12,51))>>12;

        /*if (page_address==0){
            continue;
        }*/

        //printf("PA: 0x%" PRIx64 "\n", page_address);

        
        if (!g_slist_find(p->page_write_traps, page_address)){//Trap already exist
            //printf("Not Exist\n");
            g_free(page_address);
            return;
        } else {
            printf("Exist\n");
        }
 

        new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
        new_trap->memaccess.gfn = *page_address;
        new_trap->memaccess.access = VMI_MEMACCESS_W;
        new_trap->memaccess.type = POST;
        new_trap->type = MEMACCESS;
        new_trap->cb = write_cb;
        new_trap->data = p;

        p->page_write_traps = g_slist_append(p->page_write_traps, page_address);

        drakvuf_add_trap(drakvuf, new_trap);
    }

    return;
}



void add_trap(uint64_t pa, packeranalyser *p, drakvuf_t drakvuf, vmi_instance_t vmi, page_layer pl, table_trap *parent, int init){
    drakvuf_trap_t *new_trap;
    int index_parent = -1;
    table_trap *child = (table_trap * )g_malloc0(sizeof(table_trap));
    child->pa = pa;
    child->layer = pl;
    child->init = init;


    if (pl==LAYER_PT){
        add_page_watch_pae(drakvuf, vmi, p, pa);
    }


    if (g_slist_find_custom(p->table_traps, child, custom_taple_trap_cmp_withlayer)){//Trap already exsist
        g_free(child);
        return;
    }
 
    new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->memaccess.gfn = pa>>12;
    new_trap->memaccess.access = VMI_MEMACCESS_W;
    new_trap->memaccess.type = POST;
    new_trap->name = "page_table_access_cb";
    new_trap->type = MEMACCESS;
    new_trap->cb = page_table_access_cb;
    new_trap->data = p;

    if(!drakvuf_add_trap(drakvuf, new_trap)){
        printf("Failed to add Trap to: 0x%" PRIx64 "\n", pa);
        return;
    } else {
        //printf("Added Trap to: 0x%" PRIx64 "\n", pa);
    }

    switch (pl){
        case LAYER_PDPT:
            p->table_traps = g_slist_append(p->table_traps, child);
            break;
        case LAYER_2MB:
        case LAYER_PT:
        case LAYER_PDT:
            index_parent = g_slist_position(p->table_traps, g_slist_find_custom(p->table_traps, parent, custom_taple_trap_cmp_withlayer));
            if (index_parent<0){
                p->table_traps = g_slist_append(p->table_traps, child);
            } else {
                p->table_traps = g_slist_insert(p->table_traps, child, index_parent);
            }

            break;
        default :
            printf("Huch!\n");
            break;

    }
    if (init==0){
        switch (child->layer){
            case LAYER_PDPT:
                printf("PDPT");
                break;
            case LAYER_PDT:
                printf("PDT");
                break;
            case LAYER_PT:
                printf("PT");
                break;
            case LAYER_2MB:
                printf("2MB");
                break;
        }
        printf(": 0x%" PRIx64 "\n", child->pa);
    }

    return;
}

int pae_walk(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, int init){
    table_trap *parent = (table_trap *)g_malloc0(sizeof(table_trap));
	uint64_t pdpte, pdpte_i, pdt, pdte, pt;
	uint64_t pdpt = get_pdptb(vmi_pid_to_dtb(vmi, p->pid));
	int i = 0;
    //printf("pae_walk: %i CR3: 0x%" PRIx64 "\n", p->pid, vmi_pid_to_dtb(vmi, p->pid));

    parent->pa = 0;
    parent->layer = LAYER_PT;
    parent->init = init;

	add_trap(pdpt, p, drakvuf, vmi, LAYER_PDPT, parent, init);//Add trap to the pdpt register


	for (i = 0; i < 4; ++i){//Walk the PDPT
		pdpte_i = pdpt+(i*sizeof(uint64_t));
		vmi_read_64_pa(vmi, pdpte_i, &pdpte);//Read the PDBT i

        /*if (!VMI_GET_BIT(pdpte_i, 0)){
            continue;
        }*/

		pdt = pdpte & VMI_BIT_MASK(12,51);

        parent->pa = pdpt;
        parent->layer = LAYER_PDPT;

		add_trap(pdt, p, drakvuf, vmi, LAYER_PDT, parent, init);//Add trap to the page_directory!

        parent->pa = pdt;
        parent->layer = LAYER_PDT;

        for (int count = 0; count < 512; ++count){//Walk the Page Directory Table
            vmi_read_64_pa(vmi, pdt, &pdte);//Get the Page Directory Table Entry
            /*if(!VMI_GET_BIT(pdte, 0)){
                pdt+=sizeof(uint64_t);
                continue;
            }*/
			if (VMI_GET_BIT(pdte, 7)){//2-MB-Page
                pt = pdte & VMI_BIT_MASK(21, 35);
                add_trap(pt, p, drakvuf, vmi, LAYER_2MB, parent, init);
				//printf("2MB-Page: 0x%" PRIx64 "\n", pt);
			} else {//Page Table
				pt = pdte & VMI_BIT_MASK(12, 35);
				add_trap(pt, p, drakvuf, vmi, LAYER_PT, parent, init);//Found a Page Table
			}
        pdt+=sizeof(uint64_t);
		
        }
	}

    g_free(parent);

	return 0;
}

int add_page_table_watch(drakvuf_t drakvuf, packeranalyser *p, vmi_instance_t vmi, int init) {
    //packeranalyser *p = (packeranalyser*)info->trap->data;
	page_mode pm = vmi_get_page_mode(vmi, 0);

    if (pm == VMI_PM_LEGACY){
        
    } else if (pm == VMI_PM_PAE){
        pae_walk(vmi, p, drakvuf, init);
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
