#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>

int get_layer_with_gfn(GList *layers, uint64_t page_gfn){
	layer_entry *tmp;
	for(int i = 0; i<(int)g_list_length(layers); ++i){
		GSList *iterator = (GSList *)g_list_nth_data(layers, i);
		while(iterator!=NULL){
			tmp = (layer_entry *)iterator->data;
			if(tmp->gfn == page_gfn){
				return i;
			}
			iterator = iterator->next;
		}
	}
	return -1;
}

void add_to_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn, uint layer){

	if(g_list_length(p->layers)<layer){
		printf("add_to_layer fail!\n");
		return;
	}
	layer_entry *new_entry = (layer_entry *)g_malloc(sizeof(layer_entry));

	if(layer!=0){
		drakvuf_trap_t *exec_trap;
		exec_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
		exec_trap->memaccess.gfn = page_gfn;
		exec_trap->memaccess.access = VMI_MEMACCESS_X;
		exec_trap->memaccess.type = PRE;
		exec_trap->type = MEMACCESS;
		exec_trap->cb = page_exec_cb;
		exec_trap->data = p;

        	drakvuf_add_trap(drakvuf, exec_trap);
		new_entry->trap = exec_trap;
	}

	GList *layer_element = g_list_nth(p->layers, layer);
	GSList *current_element = NULL;
	if(layer_element){
		current_element=(GSList *)layer_element->data;
	}
	
	new_entry->gfn = page_gfn;

	current_element = g_slist_append(current_element, new_entry);

	if(!layer_element){
		p->layers = g_list_append(p->layers, current_element);
	}


	return;	
}

void add_to_first_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn){
	add_to_layer(drakvuf, p, page_gfn, 0);
}

//add_to_next_layer gets called when a new address is written from an layer
void add_to_layer_with_address(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t from_va, uint64_t page_gfn){
	addr_t from_pa = vmi_translate_uv2p(vmi, from_va, p->pid);	
	int from_layer = get_layer_with_gfn(p->layers, from_pa>>12);
	int to_layer = get_layer_with_gfn(p->layers, from_pa>>12);
	if(to_layer!=-1){
		printf("add_to_next_layer: need to implement this!");
		//add_to_layer(drakvuf, p, page_gfn, to_layer);
		return;
	}
	p->layers = g_list_insert(p->layers, NULL, from_layer+1);
	add_to_layer(drakvuf, p, page_gfn, from_layer+1);
	return;
}

void switch_to_layer_with_address(drakvuf_t drakvuf, packeranalyser *p, uint64_t pa){
	layer_entry *tmp;
	int to_layer = get_layer_with_gfn(p->layers, pa>>12);	
	int from_layer = p->current_layer;
	
	GSList *to_layer_iterator = (GSList *)g_list_nth_data(p->layers, to_layer);
	
	//remove traps from the new executing layer
	while(to_layer_iterator!=NULL){
		tmp = (layer_entry *)to_layer_iterator->data;
		drakvuf_remove_trap(drakvuf, tmp->trap, (drakvuf_trap_free_t)g_free);
		tmp->trap = NULL;
		to_layer_iterator = to_layer_iterator->next;
	}
	
	GSList *from_layer_iterator = (GSList *)g_list_nth_data(p->layers, from_layer);

	//add traps to the old executing layer
	while(from_layer_iterator!=NULL){
		tmp = (layer_entry *)from_layer_iterator->data;
		drakvuf_trap_t *exec_trap;	
		exec_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
		exec_trap->memaccess.gfn = tmp->gfn;
		exec_trap->memaccess.access = VMI_MEMACCESS_X;
		exec_trap->memaccess.type = PRE;
		exec_trap->type = MEMACCESS;
		exec_trap->cb = page_exec_cb;
		exec_trap->data = p;

		drakvuf_add_trap(drakvuf, exec_trap);

		tmp->trap = exec_trap;
		from_layer_iterator = from_layer_iterator->next;
	}

	p->current_layer = to_layer;

}

