#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "page_table_watch.h"
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>

static inline uint64_t get_pdptb (uint64_t pdpr){
    return pdpr & VMI_BIT_MASK(5,63);
}
int custom_page_exec_cmp_gfn(const void* tmp1, const void* tmp2){
    layer_entry *one = (layer_entry *)tmp1;
    uint64_t *two = (uint64_t *)tmp2;

    if (unlikely((uint64_t)one->gfn==*two)){
        return 0;
    } else {
        return 1;
    }
}

int custom_page_write_cmp_address(const void* tmp1, const void* tmp2){
    uint64_t *one = (uint64_t *)tmp1;
    uint64_t *two = (uint64_t *)tmp2;

    if (unlikely(*one==*two)){
        return 0;
    } else {
        return 1;
    }
}
int custom_taple_trap_cmp_gfn(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    uint64_t *two = (uint64_t *)tmp2;

    if (unlikely((uint64_t)one->gfn==*two)){
        return 0;
    } else {
        return 1;
    }
}

int custom_table_trap_ins_index(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    table_trap *two = (table_trap *)tmp2; 

    if (unlikely(one->gfn == two->gfn && one->layer == two->layer)){
        return 0;
    } else {
        return 1;
    }
}

int custom_taple_trap_cmp_no_page(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    table_trap *two = (table_trap *)tmp2; 

    if (unlikely(one->gfn == two->gfn && one->layer != LAYER_PAGE)){
        return 0;
    } else {
        return 1;
    }
}

int custom_taple_trap_cmp_withlayer(const void* tmp1, const void* tmp2){
    table_trap *one = (table_trap *)tmp1;
    table_trap *two = (table_trap *)tmp2; 

    if (unlikely(one->gfn == two->gfn && one->layer == two->layer)){
        return 0;
    } else {
        return 1;
    }
}
void add_2mb_page_watch_pae(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t page_address, table_trap parent, int init){
    uint64_t gfn = page_address>>12;
    drakvuf_trap_t *mb_trap;

    int index_parent = g_slist_index(p->page_write_traps, &parent);

    if (index_parent<0){
        printf("add_2mb_page_watch_pae error\n");
        return;
    }

    for (int i = 0; i < 512; ++i){
        mb_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
        p->page_write_traps = g_slist_insert(p->page_write_traps, &gfn, index_parent+1);

        mb_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
        mb_trap->memaccess.gfn = gfn;
        mb_trap->memaccess.access = VMI_MEMACCESS_W;
        mb_trap->memaccess.type = POST;
        mb_trap->type = MEMACCESS;
        mb_trap->cb = write_cb;
        mb_trap->data = p;

	if(init==1){
		add_to_first_layer(drakvuf, p, gfn);
	} else {
		add_to_layer(drakvuf, p, gfn, p->current_layer);
	}

        drakvuf_add_trap(drakvuf, mb_trap);
        gfn++;
    }
}

void add_page_watch_pae(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t page_table_address, int init){
    drakvuf_trap_t *new_trap = NULL;//, *exec_trap = NULL;
    GList *parent_list = NULL;
    table_trap *child_entry = NULL, *parent_entry = NULL;
    //page_exec_trap *pet = NULL;
    uint64_t *page_gfn = NULL;
    uint64_t pte_address = 0;
    uint64_t pte = 0;
    uint64_t reserved = 0;
    uint64_t page_table_gfn = 0;
    int index_parent = -1;

    parent_entry = (table_trap *)g_malloc0(sizeof(table_trap));


    for (int i = 0; i < 512; ++i){
        page_gfn = (uint64_t *)g_malloc0(sizeof(uint64_t));
        pte_address = page_table_address+i*sizeof(uint64_t);

        vmi_read_64_pa(vmi, pte_address, &pte);//Get the Page Table Entry
        if(!VMI_GET_BIT(pte, 0)){
            continue;
        }

        reserved = (pte &  VMI_BIT_MASK(52, 60))>>52;
        if (reserved != 0){//Seems necessary otherwise we will index some weird stuff.
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


	if(init==1){
		printf("add_page_watch_pae: add_to_first_layer: 0x%" PRIx64 "\n", *page_gfn);
		add_to_first_layer(drakvuf, p, *page_gfn);
	} else {
		printf("add_page_watch_pae: add_to_layer: 0x%" PRIx64 "\n", *page_gfn);
		add_to_layer(drakvuf, p, *page_gfn, p->current_layer);
	}

        page_table_gfn = page_table_address>>12;


        parent_entry->gfn = page_table_gfn;
        parent_entry->layer = LAYER_PT;
        

        parent_list = (GList *)g_list_find_custom(p->table_traps, parent_entry, custom_taple_trap_cmp_withlayer);//Get the coressponding trable_traps entry
    

        if (parent_list == NULL){
            printf("add_page_watch_pae This shouldn't happen!: 0x%" PRIx64 "\n", page_table_address);
            continue;
        }


        child_entry = (table_trap *)g_malloc0(sizeof(table_trap));
        child_entry->gfn = *page_gfn;
        child_entry->layer = LAYER_PAGE;
        child_entry->index = i;
        child_entry->init = init;


        /*printf("add_page_watch_pae: parent: ");
        print_list_entries(parent_list->data, NULL);
        printf("child: ");
        print_list_entries(child_entry, NULL);*/


        index_parent = g_list_position(p->table_traps, parent_list);
        if (index_parent<0){
            p->table_traps = g_list_prepend(p->table_traps, child_entry);
        } else {
            p->table_traps = g_list_insert(p->table_traps, child_entry, index_parent+1);
        }



        if (init==0){
            printf("PTE_Adress: 0x%" PRIx64 " Page: 0x%" PRIx64 " PTE: 0x%" PRIx64 "\n", pte_address, *page_gfn, pte);
        }
    }

    g_free(parent_entry);

    return;
}


void add_trap(uint64_t gfn, packeranalyser *p, drakvuf_t drakvuf, vmi_instance_t vmi, page_layer pl, table_trap *parent, int init, int index){
    drakvuf_trap_t *new_trap;
    int index_parent = -1;
    table_trap *child = (table_trap * )g_malloc0(sizeof(table_trap));
    child->gfn = gfn;
    child->layer = pl;
    child->init = init;
    child->index = index;

    if (g_list_find_custom(p->table_traps, child, custom_taple_trap_cmp_withlayer)){//Trap already exist
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

    //g_list_foreach(p->table_traps, print_list_entries, NULL);

    switch (pl){
        case LAYER_PDPT:
            printf("PDPT\n");
            p->table_traps = g_list_append(p->table_traps, child);
            break;
        case LAYER_PT:
        case LAYER_PDT:
            index_parent = g_list_position(p->table_traps, g_list_find_custom(p->table_traps, parent, custom_taple_trap_cmp_withlayer));
            if (index_parent<0){
                printf("add_trap: couldn't find parent!\n");
                p->table_traps = g_list_append(p->table_traps, child);
            } else {
                p->table_traps = g_list_insert(p->table_traps, child, index_parent+1);
            }

            break;
        default :
            printf("Huch!\n");
            break;
    }
    if (init>-1){
        printf("add_trap: ");
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
            case LAYER_PAGE:
                printf("Page");
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
    parent->index = 0;
    parent->init = init;

	add_trap(pdpt>>12, p, drakvuf, vmi, LAYER_PDPT, parent, init, 0);//Add trap to the pdpt register


	for (i = 0; i < 2; ++i){//Walk the PDPT but only the lower two registers the upper two are kernel space
		pdpte_i = pdpt+(i*sizeof(uint64_t));
		vmi_read_64_pa(vmi, pdpte_i, &pdpte);//Read the PDBT i

        if (!VMI_GET_BIT(pdpte, 0)){
            continue;
        }

		pdt = (pdpte & VMI_BIT_MASK(12,51));

        parent->gfn = pdpt>>12;
        parent->layer = LAYER_PDPT;

	add_trap(pdt>>12, p, drakvuf, vmi, LAYER_PDT, parent, init, i);//Add trap to the page_directory!

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
                	add_2mb_page_watch_pae(drakvuf, vmi, p, pt, *parent, init);
		} else {//Page Table
			pt = (pdte & VMI_BIT_MASK(12, 35));
               		//printf("PT: 0x%" PRIx64 "\n", pt);
			add_trap(pt>>12, p, drakvuf, vmi, LAYER_PT, parent, init, count);
                	add_page_watch_pae(drakvuf, vmi, p, pt, init);
		}
        }
	}

    g_free(parent);

	return 0;
}

int add_page_table_watch(drakvuf_t drakvuf, packeranalyser *p, vmi_instance_t vmi, int init) {
    //packeranalyser *p = (packeranalyser*)info->trap->data;
    //drakvuf_lock_pause(drakvuf);
    drakvuf_pause(drakvuf);
    int toreturn = 0;
	page_mode pm = vmi_get_page_mode(vmi, 0);

    if (pm == VMI_PM_LEGACY){
	toreturn=-1;
    } else if (pm == VMI_PM_PAE){
        pae_walk(vmi, p, drakvuf, init);
    } else if (pm == VMI_PM_IA32E){
       	toreturn=-1;
    } else if (pm == VMI_PM_UNKNOWN){
        toreturn=-1;
    } else {
        toreturn=-1;
    }
    drakvuf_resume(drakvuf);
    //drakvuf_unlock_resume(drakvuf);
    return toreturn;

}
//TODO: remove the entries under THE entry from the lists so they get correctly reindexed
int pae_walk_from_entry(vmi_instance_t vmi, packeranalyser *p, drakvuf_t drakvuf, table_trap *parent, uint64_t pa){
    uint64_t pdte, pt=0;

    //drakvuf_lock_pause(drakvuf);

    int index = pa & VMI_BIT_MASK(3,11)>>3;//Get the index from the pa: | gfn | index in the table | offset |

    switch (parent->layer){
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
                add_2mb_page_watch_pae(drakvuf, vmi, p, pt, *parent, 0);
            } else {//Page Table
                pt = (pdte & VMI_BIT_MASK(12, 35))>>12;
                add_trap(pt, p, drakvuf, vmi, LAYER_PT, parent, 0, index);
                add_page_watch_pae(drakvuf, vmi, p, pa, 0);
            }
            break;
        case LAYER_PT://TODO: only look at the page table entry specified at pa
            pa = pa & VMI_BIT_MASK(12,51);//remove the lower 12 bits to get the starting address of the page_table
            add_page_watch_pae(drakvuf, vmi, p, pa, 0);
            break;
        case LAYER_2MB:
            add_trap(pa>>12, p, drakvuf, vmi, LAYER_2MB, parent, 0, index);
            break;
        case LAYER_PAGE:
            printf("Shouldn't happen\n");
            break;
        }
        //drakvuf_unlock_resume(drakvuf);
exit:
    //drakvuf_unlock_resume(drakvuf);
    return 0;
}


addr_t p2v(packeranalyser *p, uint64_t pa){
    int current_layer = -1, current_index = -1, offset = -1;
    uint64_t va = 0;
    GList *loop = NULL;
    table_trap *page_entry = (table_trap *)g_malloc0(sizeof(table_trap));
    page_entry->gfn = pa>>12;
    page_entry->layer = LAYER_PAGE;

    offset = pa & VMI_BIT_MASK(0, 11);

    GList *list_entry = g_list_find_custom(p->table_traps, page_entry, custom_taple_trap_cmp_withlayer);
    if (!list_entry){
        printf("p2v: Error\n");
        g_free(page_entry);
        return -1;
    }
    //list_entry_index = g_list_position(p->table_traps, list_entry);

    current_layer = ((table_trap *)list_entry->data)->layer;

    va = ((table_trap *)list_entry->data)->index<<12;

    printf("index: %i gfn: 0x%" PRIx64 " layer:%i \n", ((table_trap *)list_entry->data)->index, ((table_trap *)list_entry->data)->gfn, current_layer);

    loop = list_entry->prev;

    for (int i = 1; i < 3; ++i){
        while(((table_trap *)loop->data)->layer>=current_layer){
            loop = loop->prev;
        }
        current_index = ((table_trap *)loop->data)->index;
        current_layer = ((table_trap *)loop->data)->layer;
        printf("index: %i gfn: 0x%" PRIx64 " layer:%i \n", current_index, ((table_trap *)loop->data)->gfn, current_layer);
        va |= current_index<<(12+(i*9));

    }
    va += offset;

    g_free(page_entry);

    return va;
}
