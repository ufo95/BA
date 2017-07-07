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
int custom_page_write_cmp_address(const void* tmp1, const void* tmp2){
    uint64_t *one = (uint64_t *)tmp1;
    uint64_t *two = (uint64_t *)tmp2;

    if (*one==*two){
        return 0;
    } else {
        return 1;
    }
}

int custom_taple_trap_cmp_gfn(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    uint64_t *two = (uint64_t *)tmp2;

    if ((uint64_t)one->gfn==*two){
        return 0;
    } else {
        return 1;
    }
}

int custom_taple_trap_cmp_withlayer(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    table_trap *two = (table_trap *)tmp2; 

    if (one->gfn == two->gfn && one->layer == two->layer){
        return 0;
    } else {
        return 1;
    }
}
void add_page_watch_pae(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t page_table_address, int init){
    drakvuf_trap_t *new_trap = NULL;
    uint64_t *page_gfn = NULL;
    uint64_t pte_address = 0;
    uint64_t pte = 0;

    for (int i = 0; i < 512; ++i){
        page_gfn = (uint64_t *)g_malloc0(sizeof(uint64_t));
        pte_address = page_table_address+i*sizeof(uint64_t);

        vmi_read_64_pa(vmi, pte_address, &pte);//Get the Page Table Entry
        if(!VMI_GET_BIT(pte, 0)){
            continue;
        }

        *page_gfn = (pte & VMI_BIT_MASK(12,51))>>12;

        if (g_slist_find_custom(p->page_write_traps, page_gfn, custom_page_write_cmp_address)){//Trap already exist
            g_free(page_gfn);
            continue;
        }

        p->page_write_traps = g_slist_append(p->page_write_traps, page_gfn);

        new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
        new_trap->memaccess.gfn = (*page_gfn);
        new_trap->memaccess.access = VMI_MEMACCESS_W;
        new_trap->memaccess.type = POST;
        new_trap->type = MEMACCESS;
        new_trap->cb = write_cb;
        new_trap->data = p;

        drakvuf_add_trap(drakvuf, new_trap);

        if (init==0){
            printf("PTE_Adress: 0x%" PRIx64 " Page: 0x%" PRIx64 " PTE: 0x%" PRIx64 "\n", pte_address, *page_gfn, pte);
        }
    }


    return;
}


void add_trap(uint64_t gfn, packeranalyser *p, drakvuf_t drakvuf, vmi_instance_t vmi, page_layer pl, table_trap *parent, int init){
    drakvuf_trap_t *new_trap;
    int index_parent = -1;
    table_trap *child = (table_trap * )g_malloc0(sizeof(table_trap));
    child->gfn = gfn;
    child->layer = pl;
    child->init = init;

    if(pl==LAYER_2MB){
        if(!g_slist_find_custom(p->page_write_traps, &(child->gfn), custom_page_write_cmp_address)){
            new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

            new_trap->memaccess.gfn = child->gfn;
            new_trap->memaccess.access = VMI_MEMACCESS_W;
            new_trap->memaccess.type = POST;
            new_trap->type = MEMACCESS;
            new_trap->cb = write_cb;
            new_trap->data = p;

            p->page_write_traps = g_slist_append(p->page_write_traps, &(child->gfn));

            return;
        } else {
            return;
        }
    }

    if (g_slist_find_custom(p->table_traps, child, custom_taple_trap_cmp_withlayer)){//Trap already exist
        g_free(child);
        return;
    }
    
    new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->memaccess.gfn = child->gfn;
    new_trap->memaccess.access = VMI_MEMACCESS_W;
    new_trap->memaccess.type = POST;
    new_trap->name = "page_table_access_cb";
    new_trap->type = MEMACCESS;
    new_trap->cb = page_table_access_cb;
    new_trap->data = p;

    if(!drakvuf_add_trap(drakvuf, new_trap)){
        printf("Failed to add Trap to: 0x%" PRIx64 "\n", gfn);
        return;
    } 

    switch (pl){
        case LAYER_PDPT:
            p->table_traps = g_slist_append(p->table_traps, child);
            break;
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
        printf(": 0x%" PRIx64 "\n", child->gfn);
    }

    return;
}

int pae_walk(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, int init){
    table_trap *parent = (table_trap *)g_malloc0(sizeof(table_trap));
	uint64_t pdpte, pdpte_i, pdt, pdte, pdte_i, pt;
	uint64_t pdpt = get_pdptb(vmi_pid_to_dtb(vmi, p->pid));
	int i = 0;
    //printf("pae_walk: %i CR3: 0x%" PRIx64 "\n", p->pid, vmi_pid_to_dtb(vmi, p->pid));

    parent->gfn = 0;
    parent->layer = LAYER_PT;
    parent->init = init;

	add_trap(pdpt>>12, p, drakvuf, vmi, LAYER_PDPT, parent, init);//Add trap to the pdpt register


	for (i = 0; i < 4; ++i){//Walk the PDPT
		pdpte_i = pdpt+(i*sizeof(uint64_t));
		vmi_read_64_pa(vmi, pdpte_i, &pdpte);//Read the PDBT i

        if (!VMI_GET_BIT(pdpte, 0)){
            continue;
        }

		pdt = (pdpte & VMI_BIT_MASK(12,51));

        parent->gfn = pdpt>>12;
        parent->layer = LAYER_PDPT;

		add_trap(pdt>>12, p, drakvuf, vmi, LAYER_PDT, parent, init);//Add trap to the page_directory!

        parent->gfn = pdt>>12;
        parent->layer = LAYER_PDT;

        //printf("PDT: 0x%" PRIx64 "\n", pdt);

        for (int count = 0; count < 512; ++count){//Walk the Page Directory Table
            pdte_i = pdt+(count*sizeof(uint64_t));
            vmi_read_64_pa(vmi, pdte_i, &pdte);//Get the Page Directory Table Entry
            if(!VMI_GET_BIT(pdte, 0)){
                continue;
            }
			if (VMI_GET_BIT(pdte, 7)){//2-MB-Page
                pt = (pdte & VMI_BIT_MASK(21, 35));
                add_trap(pt>>12, p, drakvuf, vmi, LAYER_2MB, parent, init);
			} else {//Page Table
				pt = (pdte & VMI_BIT_MASK(12, 35));
               //printf("PT: 0x%" PRIx64 "\n", pt);
				add_trap(pt>>12, p, drakvuf, vmi, LAYER_PT, parent, init);
                add_page_watch_pae(drakvuf, vmi, p, pt, init);
			}
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

int pae_walk_from_entry(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, table_trap *entry, uint64_t pa){
    uint64_t pdte, pt=0;

    table_trap *parent = (table_trap *)g_malloc0(sizeof(table_trap));

    parent->gfn = -1;
    parent->layer = LAYER_PT;
    parent->init = 0;


    switch (entry->layer){
        case LAYER_PDPT:
            if((pa-get_pdptb(vmi_pid_to_dtb(vmi, p->pid)))>(3*sizeof(uint64_t))){//The entry->pa is not pointing at our pdpt so ignore it
                goto exit;
            }
            pae_walk(vmi, p, drakvuf, 0);
            break;
        case LAYER_PDT:
            vmi_read_64_pa(vmi, pa, &pdte);//Get the Page Directory Table Entry
            if(!VMI_GET_BIT(pdte, 0)){
                goto exit; 
            }
            if (VMI_GET_BIT(pdte, 7)){//2-MB-Page
                pt = (pdte & VMI_BIT_MASK(21, 35))>>12;
                add_trap(pt, p, drakvuf, vmi, LAYER_2MB, parent, 0);
            } else {//Page Table
                pt = (pdte & VMI_BIT_MASK(12, 35))>>12;
                add_trap(pt, p, drakvuf, vmi, LAYER_PT, parent, 0);
                add_page_watch_pae(drakvuf, vmi, p, pa, 0);
            }
            break;
        case LAYER_PT://TODO: only look at the page table entry specified at pa
            pa = pa & VMI_BIT_MASK(12,51);//remove the lower 12 bits to get the starting address of the page_table
            add_page_watch_pae(drakvuf, vmi, p, pa, 0);
            break;
        case LAYER_2MB:
            add_trap(pa>>12, p, drakvuf, vmi, LAYER_2MB, parent, 0);
            break;
        }

exit:
    g_free(parent);        
    return 0;
}
