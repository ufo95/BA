#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>

void print_layers(GList *layers){
	layer_entry *tmp;
	printf("---LAYERS---\n");
	for(int i = 0; i<(int)g_list_length(layers); ++i){
		printf("layer %i\n", i);
		GList *entry = g_list_nth(layers, i);
		if(!entry)
			continue;
		GSList *iterator = (GSList *)entry->data;
		while(iterator!=NULL){
			tmp = (layer_entry *)iterator->data;
			if(tmp)
				printf("0x%" PRIx64 "\n", tmp->gfn);
			iterator = iterator->next;
		}
	}
}


int get_layer_with_gfn(GList *layers, uint64_t page_gfn){
	layer_entry *tmp;
	printf("get_layer---LAYERS---\n");
	for(int i = 0; i<(int)g_list_length(layers); ++i){
		GList *entry = g_list_nth(layers, i);
		if(!entry)
			continue;
		GSList *iterator = (GSList *)entry->data;
		printf("layer %i\n", i);
		while(iterator!=NULL){
			tmp = (layer_entry *)iterator->data;
			if(tmp)
				printf("0x%" PRIx64 "\n", tmp->gfn);
			if(tmp && tmp->gfn == page_gfn){
				return i;
			}
			iterator = iterator->next;
		}
	}
	return -2;
}

void add_to_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn, int layer){

	if((int)g_list_length(p->layers)<layer){
		printf("add_to_layer fail!\n");
		return;
	}
	layer_entry *new_entry = (layer_entry *)g_malloc(sizeof(layer_entry));

	printf("Adding execution trap\n");
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
	
	GSList *layer_list = (GSList *)g_list_nth_data(p->layers, layer);
	layer_list = (GSList *)g_slist_append(layer_list, new_entry);
	
	if(!g_list_nth(p->layers, layer)){
		printf("New Layer\n");
		p->layers = g_list_append(p->layers, layer_list);
	} 
	
	print_layers(p->layers);

	return;	
}

void add_to_first_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn){
	add_to_layer(drakvuf, p, page_gfn, 0);
}

//add_to_next_layer gets called when a new address is written from an layer
void add_to_layer_with_address(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t from_va, uint64_t page_gfn){
	addr_t from_pa = vmi_pagetable_lookup(vmi, vmi_pid_to_dtb(vmi, p->pid), from_va);	
	int from_layer = p->current_layer+1;
	//int from_layer = get_layer_with_gfn(p->layers, from_pa>>12);	
	int to_layer = get_layer_with_gfn(p->layers, page_gfn);
	printf("add_to_layer_with_address: current: %i from: %i to: %i\n", p->current_layer, from_layer, to_layer);

	if(to_layer!=-1){
		printf("to_layer known: 0x%" PRIx64 "\n", page_gfn);
		return;
	}
	if(from_layer==-2){
		printf("from_layer unknown: 0x%" PRIx64 "\n", from_pa);	
	}	
	add_to_layer(drakvuf, p, page_gfn, from_layer);
	return;
}

void switch_to_layer_with_address(drakvuf_t drakvuf, packeranalyser *p, uint64_t pa){
	layer_entry *tmp;
	int to_layer = get_layer_with_gfn(p->layers, pa>>12);	
	int from_layer = p->current_layer;
	
	printf("Going to switch from: %i, to %i\n", to_layer, from_layer);
	GSList *to_layer_iterator = (GSList *)g_list_nth_data(p->layers, to_layer);
	
	//remove traps from the new executing layer
	while(to_layer_iterator!=NULL){
		tmp = (layer_entry *)to_layer_iterator->data;
		if(tmp&&tmp->trap){
			drakvuf_remove_trap(drakvuf, tmp->trap, (drakvuf_trap_free_t)g_free);
		} else {
			printf("Didn't find trap for 0x%" PRIx64 "\n", pa);
		}
		tmp->trap = NULL;
		to_layer_iterator = to_layer_iterator->next;
	}

	GSList *from_layer_iterator = NULL;
	if(p->current_layer>=0){
		from_layer_iterator = (GSList *)g_list_nth_data(p->layers, from_layer);
	}

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

