#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "layers.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>


void print_frame(gpointer *frame_ptr){
	printf("0x%" PRIx64 " %p\n", ((frame*)frame_ptr)->gfn, &((frame *)frame_ptr)->gfn);
}

void print_layers(packeranalyser *p){
	printf("---LAYERS---\n");
	for(int i = 0; i<(int)g_list_length(p->layers); i++){
		printf("layer %i\n", i);
		layer_entry *entry = (layer_entry*)g_list_nth_data(p->layers, i);
		if(!entry)
			continue;
		g_slist_foreach(entry->frames, (GFunc)print_frame, NULL);

	}
}

int custom_layer_cmp_gfn(const void* tmp1, const void* tmp2){
	uint64_t one = ((frame *)tmp1)->gfn;
	uint64_t *two = (uint64_t *)tmp2;
	if(one==*two){
		return 0;
	} else {
		return 1;
	}

}


int get_layer_with_gfn(GList *layers, uint64_t page_gfn){
	for(int i = 0; i<(int)g_list_length(layers); i++){
		layer_entry* entry = (layer_entry *)g_list_nth_data(layers, i);
		if(!entry)
			continue;
		GSList *iterator = (GSList *)entry->frames;
		if(g_slist_find_custom(iterator, &page_gfn, custom_layer_cmp_gfn)){
			return i;
		}
	}
	return -2;
}

void add_to_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn, int layer_index){
	printf("%s \n", __FUNCTION__);
	if((int)g_list_length(p->layers)<layer_index){
		printf("add_to_layer error\n");
	}

	frame *new_entry = (frame *)g_malloc0(sizeof(frame));

	if(layer_index!=0){//init layer is already active
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
		new_entry->exec_trap = exec_trap;

		drakvuf_trap_t *write_trap;
		write_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

		write_trap->memaccess.gfn = page_gfn;
		write_trap->memaccess.access = VMI_MEMACCESS_W;
		write_trap->memaccess.type = PRE;
		write_trap->type = MEMACCESS;
		write_trap->cb = write_cb;
		write_trap->data = p;

		drakvuf_add_trap(drakvuf, write_trap);
		new_entry->write_trap = write_trap;
	}

	new_entry->gfn = page_gfn;
	printf("%s %" PRIx64 " Exec: %p Write: %p\n", __FUNCTION__, new_entry->gfn, new_entry->exec_trap, new_entry->write_trap);	

	layer_entry *layer = (layer_entry *)g_list_nth_data(p->layers, layer_index);

	if(!layer){
		layer = (layer_entry *)g_malloc0(sizeof(layer_entry));
		p->layers = g_list_insert(p->layers, layer, layer_index);
	}
	layer->frames = (GSList *)g_slist_append(layer->frames, new_entry);
	//print_layers(p);

	return;	
}

void add_to_first_layer(drakvuf_t drakvuf, packeranalyser *p, uint64_t page_gfn){
	add_to_layer(drakvuf, p, page_gfn, 0);
}

//add_to_next_layer gets called when a new address is written from a layer
void add_to_layer_with_address(drakvuf_t drakvuf, vmi_instance_t vmi, packeranalyser *p, uint64_t from_va, uint64_t page_gfn){
	//printf("%s \n", __FUNCTION__);
	addr_t from_pa = vmi_pagetable_lookup(vmi, vmi_pid_to_dtb(vmi, p->pid), from_va);	
	int from_layer = get_layer_with_gfn(p->layers, from_pa>>12);
	int to_layer = get_layer_with_gfn(p->layers, page_gfn);
	if(from_layer == -2){//this is probably the kernel writing
		//printf("add_to_layer_with_address: from_layer not known\n");
		from_layer = p->current_exec_layer;
	}

	if(to_layer==-2){//This page is not in a layer yet -> this page belongs to from_layer +1
		add_to_layer(drakvuf, p, page_gfn, p->current_exec_layer+1);
		printf("page_gfn: 0x%" PRIx64 " from_va 0x%" PRIx64 " from_pa: 0x%" PRIx64 "\n", page_gfn, from_va, from_pa);
		printf("add_to_layer_with_address: current: %i from: %i to: %i\n", p->current_exec_layer, from_layer, to_layer);//From layer should be the same as p->current_exec_layer
	} else {//This page is already in a layer maybe update the written_from var. If so that means multi frame packer
		layer_entry *to_entry = (layer_entry *)g_list_nth_data(p->layers, to_layer);
		if(to_entry->wrote_from<from_layer)
			to_entry->wrote_from=from_layer;
	}

	return;
}

void switch_to_layer_with_address(drakvuf_t drakvuf, packeranalyser *p, uint64_t pa){
	frame *tmp;
	int to_layer = get_layer_with_gfn(p->layers, pa>>12);	
	int from_layer = p->current_exec_layer;
	
	printf("switch_to_layer_with_address: Going to switch from: %i, to %i current: %i\n", from_layer, to_layer, p->current_exec_layer);
	if(to_layer == from_layer){
		print_layers(p);
		printf("Why should this happen?, 0x%" PRIx64 "\n", pa);
		return;
	}
	layer_entry *le = (layer_entry *)g_list_nth_data(p->layers, to_layer);
	GSList *to_layer_iterator = (GSList *)le->frames;

	//remove traps from the new executing layer
	int i = -1;
	while(to_layer_iterator!=NULL){//use for_each?
		i++;
		tmp = (frame *)to_layer_iterator->data;
			if(tmp && ((!tmp->exec_trap && tmp->write_trap)
			   || (tmp->exec_trap && !tmp->write_trap))){
				printf("%" PRIx64 " Exec: %p Write: %p\n", tmp->gfn, tmp->exec_trap, tmp->write_trap);	
				printf("FOOOO!\n");
				print_layers(p);
				exit(1);
			}
		if(tmp&&tmp->exec_trap&&tmp->write_trap){
			drakvuf_remove_trap(drakvuf, tmp->exec_trap, (drakvuf_trap_free_t)g_free);
			drakvuf_remove_trap(drakvuf, tmp->write_trap, (drakvuf_trap_free_t)g_free);
			tmp->exec_trap = NULL;
			tmp->write_trap = NULL;
		} else {
			printf("Didn't find trap for 0x%" PRIx64 "\n", pa);
		}
		to_layer_iterator = to_layer_iterator->next;
	}

	GSList *from_layer_iterator = NULL;
	if(p->current_exec_layer>=0){
		layer_entry *from_layer_entry = (layer_entry *)g_list_nth_data(p->layers, from_layer);
		from_layer_iterator = (GSList *)from_layer_entry->frames;
	}

	//add traps to the old executing layer
	while(from_layer_iterator!=NULL){//use for_each?
		tmp = (frame *)from_layer_iterator->data;
		if (tmp->exec_trap || tmp->write_trap){
			printf("Warum genau existieren die schon?\n");
			printf("Und wenn müssen die nicht weg?\n");
			exit(1);
		}
		drakvuf_trap_t *exec_trap;	
		exec_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
		exec_trap->memaccess.gfn = (tmp->gfn);
		exec_trap->memaccess.access = VMI_MEMACCESS_X;
		exec_trap->memaccess.type = PRE;
		exec_trap->type = MEMACCESS;
		exec_trap->cb = page_exec_cb;
		exec_trap->data = p;

		drakvuf_add_trap(drakvuf, exec_trap);
		tmp->exec_trap = exec_trap;

		drakvuf_trap_t *write_trap;
		write_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
		write_trap->memaccess.gfn = tmp->gfn;
		write_trap->memaccess.access = VMI_MEMACCESS_W;
		write_trap->memaccess.type = PRE;
		write_trap->type = MEMACCESS;
		write_trap->cb = write_cb;
		write_trap->data = p;

		drakvuf_add_trap(drakvuf, write_trap);
		tmp->write_trap = write_trap;
		from_layer_iterator = from_layer_iterator->next;
	}

	layer_entry *to_entry = (layer_entry *)g_list_nth(p->layers, to_layer);
       	if(to_entry->executed_from<from_layer)
		to_entry->executed_from = from_layer;

	p->current_exec_layer = to_layer;

	//p->current_write_layer = -1;
}

