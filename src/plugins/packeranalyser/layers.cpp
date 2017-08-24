#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>


void print_frame(gpointer *frame_ptr){
	printf("0x%" PRIx64 "\n", ((frame*)frame_ptr)->gfn);
}

void print_layers(packeranalyser *p){
	printf("---LAYERS---\n");
	for(int i = 0; i<(int)g_list_length(p->layers); ++i){
		printf("layer %i\n", i);
		layer_entry *entry = (layer_entry*)g_list_nth_data(p->layers, i);
		if(!entry)
			continue;
		g_slist_foreach(entry->frames, (GFunc)print_frame, NULL);

	}
}


int get_layer_with_gfn(GList *layers, uint64_t page_gfn){//Doesn't work yet! Needs a rewrite!
	frame *tmp;
	for(int i = 0; i<(int)g_list_length(layers); ++i){
		 layer_entry* entry = (layer_entry *)g_list_nth_data(layers, i);
		if(!entry)
			continue;
		GSList *iterator = (GSList *)entry->frames;
		while(iterator){
			tmp = (frame *)iterator->data;
			if(tmp && tmp->gfn == page_gfn){
				return i;
			}
			iterator = iterator->next;
		}
	}
	return -2;
}

void add_to_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn, int layer_index){

	if((int)g_list_length(p->layers)<layer_index){
		printf("add_to_layer error\n");
	}

	frame *new_entry = (frame *)g_malloc(sizeof(frame));

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
	new_entry->gfn = page_gfn;

	layer_entry *layer = (layer_entry *)g_list_nth_data(p->layers, layer_index);
	if(!layer){
		layer = (layer_entry *)g_malloc0(sizeof(layer_entry));
		layer->frames = (GSList *)g_slist_append(layer->frames, new_entry);
		p->layers = g_list_insert(p->layers, layer, layer_index);
	} else {
		layer->frames = (GSList *)g_slist_append(layer->frames, new_entry);
	}
	print_layers(p);

	return;	
}

void add_to_first_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn){
	add_to_layer(drakvuf, p, page_gfn, 0);
}

//add_to_next_layer gets called when a new address is written from a layer
void add_to_layer_with_address(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t from_va, uint64_t page_gfn){
	addr_t from_pa = vmi_pagetable_lookup(vmi, vmi_pid_to_dtb(vmi, p->pid), from_va);	
	int from_layer = get_layer_with_gfn(p->layers, from_pa>>12);
	int to_layer = get_layer_with_gfn(p->layers, page_gfn);
	printf("page_gfn: 0x%" PRIx64 " from_va 0x%" PRIx64 " from_pa: 0x%" PRIx64 "\n", page_gfn, from_va, from_pa);
	printf("add_to_layer_with_address: current: %i from: %i to: %i\n", p->current_exec_layer, from_layer, to_layer);
	if(to_layer==-2){//writing to a new layer
		layer_entry *new_layer = (layer_entry *)g_malloc0(sizeof(layer_entry));
		new_layer->wrote_from = from_layer;
		p->current_write_layer = (int)g_list_length(p->layers);
		p->layers = (GList *)g_list_append(p->layers, new_layer);
	} else {
		p->current_write_layer = to_layer;
		layer_entry *to_entry = (layer_entry *)g_list_nth_data(p->layers, to_layer);
		if(to_entry->wrote_from<to_layer)
			to_entry->wrote_from=to_layer;
	}

	add_to_layer(drakvuf, p, page_gfn, to_layer);
	return;
}

void switch_to_layer_with_address(drakvuf_t drakvuf, packeranalyser *p, uint64_t pa){
	frame *tmp;
	int to_layer = get_layer_with_gfn(p->layers, pa>>12);	
	int from_layer = p->current_exec_layer;
	
	printf("Going to switch from: %i, to %i\n", to_layer, from_layer);
	GSList *to_layer_iterator = (GSList *)g_list_nth_data(p->layers, to_layer);
	
	//remove traps from the new executing layer
	while(to_layer_iterator!=NULL){
		tmp = (frame *)to_layer_iterator->data;
		if(tmp&&tmp->trap){
			drakvuf_remove_trap(drakvuf, tmp->trap, (drakvuf_trap_free_t)g_free);
		} else {
			printf("Didn't find trap for 0x%" PRIx64 "\n", pa);
		}
		tmp->trap = NULL;
		to_layer_iterator = to_layer_iterator->next;
	}

	GSList *from_layer_iterator = NULL;
	if(p->current_exec_layer>=0){
		from_layer_iterator = (GSList *)g_list_nth_data(p->layers, from_layer);
	}

	//add traps to the old executing layer
	while(from_layer_iterator!=NULL){
		tmp = (frame *)from_layer_iterator->data;
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

	layer_entry *to_entry = (layer_entry *)g_list_nth(p->layers, to_layer);
       	if(to_entry->executed_from<from_layer)
		to_entry->executed_from = from_layer;

	p->current_exec_layer = to_layer;

	p->current_write_layer = -1;
}

