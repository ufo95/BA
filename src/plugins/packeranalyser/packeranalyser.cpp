#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>

//TODO: Refactor code so that only one syscall argument read function is needed
static event_response_t execution_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    printf("!!!!!!!!!!!!!!!Execution_CB_TRAP!!!!!!!!!!!!!!!!!!!!%" PRIx64 "\n", info->trap_pa);
    return 0;
}

static event_response_t recover_address_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    addr_t gfn;
    return_address_data *rad = (return_address_data*)info->trap->data;
    packeranalyser *p = (packeranalyser *)rad->p;
    addr_t address_pointer = (addr_t)rad->address_pointer;
    drakvuf_trap_t *new_trap = NULL;


    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if(p->pid != (int) vmi_dtb_to_pid (vmi, info->regs->cr3)){
        drakvuf_release_vmi(drakvuf);
        return 0;
    }
    //TODO: check return value in eax if allocation was successful

    /*if (info->regs->rax!=0){
        printf("Allocation not successful\n");
        drakvuf_release_vmi(drakvuf);
        return 0;
    }*/


    uint8_t reg_size = vmi_get_address_width(vmi);
    size_t size = 0;
    unsigned char* buf = NULL;
    uint32_t *buf32 = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    size = reg_size * 2;

    buf  = (unsigned char *)g_malloc0(sizeof(char)*size);

    buf32 = (uint32_t *)buf;
    
        //NTAllocateVirtualMemory clears 0x18 from stack
    ctx.addr = info->regs->rsp-0x14;

    if(reg_size == vmi_read(vmi, &ctx, &buf32[1], reg_size)){
        ctx.addr = buf32[1];
        if(reg_size != vmi_read(vmi, &ctx, &buf32[1], reg_size)){
            printf("ERROR 2\n");
        }
    } else {
        printf("ERROR 1\n");
    }


    ctx.addr = address_pointer;
    
    if(reg_size != vmi_read(vmi, &ctx, &buf32[0], reg_size)){
        printf("ERROR\n");
    }

    printf("RSP-0x14: 0x%" PRIx32 " address_pointer 0x%" PRIx32 "\n", buf32[1], buf32[0]);

    //Adding Trap to be called if page with new excutable rights get accesssed
    //get the page address
    gfn = vmi_pagetable_lookup(vmi, info->regs->cr3, buf32[0]);
    //gfn = vmi_translate_uv2p(vmi, buf32[0], p->pid);

    if (gfn == 0){
        printf("No matching page found: %s, 0x%" PRIx64 ", 0x%" PRIx32 " ctx: 0x%" PRIx64 " rax: 0x%" PRIx64 "\n", info->trap->name, address_pointer, (unsigned int)buf32[0], ctx.addr, info->regs->rax);
        goto exit;
    } else {
        printf("Found matching page: %s, 0x%" PRIx64 ", 0x%" PRIx32 " ctx: 0x%" PRIx64 " rax: 0x%" PRIx64 "\n", info->trap->name, address_pointer, (unsigned int)buf32[0], ctx.addr, info->regs->rax);
    }

    new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->memaccess.gfn = gfn;
    new_trap->memaccess.access = VMI_MEMACCESS_RWX;
    new_trap->memaccess.type = POST;
    new_trap->name = "execution_cb_trap";
    new_trap->type = MEMACCESS;
    new_trap->cb = execution_cb;
    new_trap->data = p;

    //printf("New execution_cb_trap registered gfn: 0x%" PRIx32 " address: 0x%" PRIx32 "\n", (unsigned int)gfn, buf32[0]);

    if ( !drakvuf_add_trap(drakvuf, new_trap) ){
        printf("Couldn't add trap\n");; 
    } else {
        p->execution_cb_trap = g_slist_prepend(p->execution_cb_trap, new_trap);
    }

    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    p->get_address_trap = g_slist_remove(p->get_address_trap, info->trap);

exit:
    g_free(buf);
    drakvuf_release_vmi(drakvuf);
  
    return 0;
}

int recover_address(drakvuf_t drakvuf, drakvuf_trap_info_t *info, vmi_instance_t *vmi, addr_t address_pointer){
    //To get the address we need to set a breakpoint at the return adress so we get the result address of the allocation
    packeranalyser *p = (packeranalyser*)info->trap->data;
    return_address_data *rad = (return_address_data *)g_malloc0(sizeof(return_address_data));
    uint32_t return_address = 0, resolved_address_pointer;
    access_context_t ctx;

    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = info->regs->rsp;

    vmi_read_32(*vmi, &ctx, &return_address);//read the return address from the stack
    
    //printf("address_pointer: 0x%" PRIx32 " return_address: 0x%" PRIx32 "\n", (unsigned int)address_pointer, (unsigned int) return_address);

   
    //Since WinApi calls are stdcall we need to get the pointer to the allocated address beforehand and give it to the callback so it can read the returned address after the allocation took place
    rad->p = p,
    rad->address_pointer = (addr_t)address_pointer;

    ctx.addr = address_pointer;
    vmi_read_32(*vmi, &ctx, &resolved_address_pointer);

    printf("address_pointer 0x%" PRIx64 " *address_pointer 0x%" PRIx32 "\n", address_pointer, resolved_address_pointer);

    drakvuf_trap_t *new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->breakpoint.lookup_type = LOOKUP_PID;
    new_trap->breakpoint.pid = p->pid;
    new_trap->breakpoint.addr_type = ADDR_VA;
    new_trap->breakpoint.module = "Win32Project1_packed.exe";
    new_trap->name = info->trap->name;
    new_trap->type = BREAKPOINT;
    new_trap->cb = recover_address_cb;
    new_trap->data = rad;

    new_trap->breakpoint.addr = (addr_t)return_address;

    if ( !drakvuf_add_trap(drakvuf, new_trap) ){
            printf("Couldn't add trap\n");; 
    }

    p->get_address_trap = g_slist_prepend(p->get_address_trap, new_trap);


    return 0;
}


static event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    packeranalyser *p = (packeranalyser*)info->trap->data;

    int number_of_args = 0, index_address = 0, index_protect = 0, need_recover=0;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unsigned char *buf = NULL;
    uint8_t reg_size = vmi_get_address_width(vmi);
    size_t size = 0;
    uint32_t *buf32 = NULL;
    uint64_t *buf64 = NULL;
    addr_t gfn;
    //drakvuf_trap_t *new_trap=NULL;


    if(p->pid != (int) vmi_dtb_to_pid (vmi, info->regs->cr3)){
        drakvuf_release_vmi(drakvuf);
        return 0;
    }


    //TODO: get the size argument for index_address = 0 functions so we can calculate the memory region
    //printf("Trap: %s\n", info->trap->name);
    if(!strcmp(info->trap->name, "NtProtectVirtualMemory")){
        number_of_args = 5;
        index_address = 1;
        index_protect = 3;
        need_recover = 0;
    } else if (!strcmp(info->trap->name, "NtAllocateVirtualMemory")){
        number_of_args = 6;
        index_address = 1;
        index_protect = 5;
        need_recover = 1;//We need recover_address to get the resulting adress
    } else if (!strcmp(info->trap->name, "NtMapViewOfSection")){
        number_of_args = 10;
        index_address = 2;
        index_protect = 9;
        need_recover = 1;//We need recover_address to get the resulting adress
    } else {
        printf("Error in syscall_cb: Do not know the trapped syscall\n");
        goto exit;
    }

    size = reg_size * number_of_args;

    buf  = (unsigned char *)g_malloc(sizeof(char)*size);

    buf32 = (uint32_t *)buf;
    buf64 = (uint64_t *)buf;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;


    if ( 4 == reg_size ){
            // 32 bit os
            ctx.addr = info->regs->rsp + reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( size != vmi_read(vmi, &ctx, buf, size) ){
                printf("Error 1\n");
                goto exit;
            }

        if(need_recover==1){
            recover_address(drakvuf, info, &vmi, buf32[index_address]);
            goto exit;
        } else {
            ctx.addr = buf32[index_address];
            if(VMI_SUCCESS != vmi_read_32(vmi, &ctx, &buf32[index_address])){
                printf("ERROR\n");
            }
        }

    }
    printf("Callback: %s Adress: 0x%" PRIx32 " Protect: 0x%" PRIx32 "\n", info->trap->name, buf32[index_address], buf32[index_protect]);

    gfn = vmi_pagetable_lookup (vmi, info->regs->cr3, buf32[0]);

    if (gfn == 0){
        printf("No matching page found: %s, 0x%" PRIx32 "\n", info->trap->name, (unsigned int)buf32[0]);
        goto exit;
    }


    /*new_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));

    new_trap->memaccess.gfn = gfn;
    new_trap->memaccess.access = VMI_MEMACCESS_RWX;
    new_trap->memaccess.type = PRE;
    new_trap->name = "execution_cb_trap";
    new_trap->type = MEMACCESS;
    new_trap->cb = execution_cb;
    new_trap->data = p;

    if ( !drakvuf_add_trap(drakvuf, new_trap) ){
        printf("Couldn't add trap\n");; 
    } else {
        p->execution_cb_trap = g_slist_prepend(p->execution_cb_trap, new_trap);
        printf("execution_cb_trap: %i\n", g_slist_length(p->execution_cb_trap));
    }*/

    exit:
        g_free(buf);
        drakvuf_release_vmi(drakvuf);
        return 0;
    
}


static event_response_t ntcontinue_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    packeranalyser *p = (packeranalyser*)info->trap->data;
    if(p->trap==0){
        p->trap=1;
    } else {
        return 0;
    }

    p->first_cb_trap.breakpoint.lookup_type = LOOKUP_PID;
    p->first_cb_trap.breakpoint.pid = 4;
    p->first_cb_trap.breakpoint.addr_type = ADDR_RVA;
    p->first_cb_trap.breakpoint.module = "ntoskrnl.exe";
    p->first_cb_trap.name = "NtAllocateVirtualMemory";
    p->first_cb_trap.type = BREAKPOINT;
    p->first_cb_trap.cb = syscall_cb;
    p->first_cb_trap.data = p;

    p->ntpvm_cb_trap.breakpoint.lookup_type = LOOKUP_PID;
    p->ntpvm_cb_trap.breakpoint.pid = 4;
    p->ntpvm_cb_trap.breakpoint.addr_type = ADDR_RVA;
    p->ntpvm_cb_trap.breakpoint.module = "ntoskrnl.exe";
    p->ntpvm_cb_trap.name = "NtProtectVirtualMemory";
    p->ntpvm_cb_trap.type = BREAKPOINT;
    p->ntpvm_cb_trap.cb = syscall_cb;
    p->ntpvm_cb_trap.data = p;

    p->thrd_cb_trap.breakpoint.lookup_type = LOOKUP_PID;
    p->thrd_cb_trap.breakpoint.pid = 4;
    p->thrd_cb_trap.breakpoint.addr_type = ADDR_RVA;
    p->thrd_cb_trap.breakpoint.module = "ntoskrnl.exe";
    p->thrd_cb_trap.name = "NtMapViewOfSection";
    p->thrd_cb_trap.type = BREAKPOINT;
    p->thrd_cb_trap.cb = syscall_cb;
    p->thrd_cb_trap.data = p;


    if ( !drakvuf_get_function_rva(p->r_p, "NtAllocateVirtualMemory", &p->first_cb_trap.breakpoint.rva) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &p->first_cb_trap) )
        throw -1; 

    if ( !drakvuf_get_function_rva(p->r_p, "NtProtectVirtualMemory", &p->ntpvm_cb_trap.breakpoint.rva) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &p->ntpvm_cb_trap) )
        throw -1;

   if ( !drakvuf_get_function_rva(p->r_p, "NtMapViewOfSection", &p->thrd_cb_trap.breakpoint.rva) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &p->thrd_cb_trap) )
        throw -1;


    return 0;

}

packeranalyser::packeranalyser(drakvuf_t drakvuf, const void *config_p, output_format_t output){
	const struct packeranalyser_config *p = (const struct packeranalyser_config *)config_p;


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

	if (this->pm == VMI_PM_IA32E){
		printf("VMI_PM_IA32E\n");
    }

    if(vmi_get_address_width(vmi)==8){
        printf("64 bit not yet supporter\n");
        throw -1;
    }

    this->ntcontinuecb_trap.breakpoint.lookup_type = LOOKUP_PID;
    this->ntcontinuecb_trap.breakpoint.pid = 4;
    this->ntcontinuecb_trap.breakpoint.addr_type = ADDR_RVA;
    this->ntcontinuecb_trap.breakpoint.module = "ntoskrnl.exe";
    this->ntcontinuecb_trap.name = "NtContinue";
    this->ntcontinuecb_trap.type = BREAKPOINT;
    this->ntcontinuecb_trap.cb = ntcontinue_cb;
    this->ntcontinuecb_trap.data = (void*)this;

    if ( !drakvuf_get_function_rva(this->r_p, "NtContinue", &this->ntcontinuecb_trap.breakpoint.rva) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->ntcontinuecb_trap) )
        throw -1; 




}



packeranalyser::~packeranalyser() {
	printf("Goodbye!\n");
}

