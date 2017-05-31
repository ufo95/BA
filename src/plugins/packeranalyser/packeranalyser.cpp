#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"
#include "../plugins.h"
#include <libdrakvuf/libdrakvuf.h>
static event_response_t thrd_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    packeranalyser *p = (packeranalyser*)info->trap->data;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unsigned char *buf = NULL;

    if(p->pid != (int) vmi_dtb_to_pid (vmi, info->regs->cr3)){
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    uint8_t reg_size = vmi_get_address_width(vmi);
    size_t size = reg_size * 9;

    buf  = (unsigned char *)g_malloc(sizeof(char)*size);

    uint32_t *buf32 = (uint32_t *)buf;
    uint64_t *buf64 = (uint64_t *)buf;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

  if ( 4 == reg_size ){
            // 32 bit os
            ctx.addr = info->regs->rsp + reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( size != vmi_read(vmi, &ctx, buf, size) )
                goto exit;
    }

    if ( 8 == reg_size ){
            // first 4 agrs passed via rcx, rdx, r8, and r9
            ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
            size_t sp_size = reg_size * (2);
            if ( sp_size != vmi_read(vmi, &ctx, &(buf64[4]), sp_size) )
                goto exit;
    }

    
    if ((buf32[9]&0xF0)==0){//Checks if execute right is requested 
        goto exit;
    }

        //printf(" Arguments: %" PRIu32 "\n", 6);
    printf("NtMapViewOfSection ");

    if ( 4 == reg_size ){
        ctx.addr = buf32[2];
        if(VMI_SUCCESS != vmi_read_32(vmi, &ctx, &buf32[2])){
            printf("ERROR\n");
        }
        printf("baseaddress 0x%" PRIx32 " ViewSize 0x%" PRIx32 " Protect 0x%" PRIx32, buf32[2], buf32[6],buf32[9]);
        
    }else{
        //printf("0x%" PRIx64, buf64[i]);
    }
    printf("\n");

exit:
    drakvuf_release_vmi(drakvuf);
    g_free(buf);



    return 0;


}

static event_response_t ntpvm_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    packeranalyser *p = (packeranalyser*)info->trap->data;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unsigned char *buf = NULL;

    if(p->pid != (int) vmi_dtb_to_pid (vmi, info->regs->cr3)){
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    uint8_t reg_size = vmi_get_address_width(vmi);
    size_t size = reg_size * 6;

    buf  = (unsigned char *)g_malloc(sizeof(char)*5);

    uint32_t *buf32 = (uint32_t *)buf;
    uint64_t *buf64 = (uint64_t *)buf;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

  if ( 4 == reg_size ){
            // 32 bit os
            ctx.addr = info->regs->rsp + reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( size != vmi_read(vmi, &ctx, buf, size) )
                goto exit;
    }

    if ( 8 == reg_size ){
            // first 4 agrs passed via rcx, rdx, r8, and r9
            ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
            size_t sp_size = reg_size * (2);
            if ( sp_size != vmi_read(vmi, &ctx, &(buf64[4]), sp_size) )
                goto exit;
    }

    if ( 4 == reg_size ){
        //follow baseaddress and regionsize pointer
        ctx.addr = buf32[1];
        if(VMI_SUCCESS != vmi_read_32(vmi, &ctx, &buf32[1])){
            printf("ERROR\n");
        }

        ctx.addr = buf32[2];
        if(VMI_SUCCESS != vmi_read_32(vmi, &ctx, &buf32[2])){
            printf("ERROR\n");
        }

        ctx.addr = buf32[4];
        if(VMI_SUCCESS != vmi_read_32(vmi, &ctx, &buf32[4])){
            printf("ERROR\n");
        }

        for (int i = 1; i < 5; ++i){
            printf(" 0x%" PRIx32, buf32[i]);
        }
    }else{
        //printf("0x%" PRIx64, buf64[i]);
    }
    printf("\n");

exit:
    drakvuf_release_vmi(drakvuf);



    return 0;
}


static event_response_t first_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
	packeranalyser *p = (packeranalyser*)info->trap->data;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unsigned char *buf = NULL;

    if(p->pid != (int) vmi_dtb_to_pid (vmi, info->regs->cr3)){
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    uint8_t reg_size = vmi_get_address_width(vmi);
    size_t size = reg_size * 6;

    buf  = (unsigned char *)g_malloc(sizeof(char)*4);

    uint32_t *buf32 = (uint32_t *)buf;
    uint64_t *buf64 = (uint64_t *)buf;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;


    if ( 4 == reg_size ){
            // 32 bit os
            ctx.addr = info->regs->rsp + reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( size != vmi_read(vmi, &ctx, buf, size) )
                goto exit;
    }

    if ( 8 == reg_size ){
            // first 4 agrs passed via rcx, rdx, r8, and r9
            ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
            size_t sp_size = reg_size * (2);
            if ( sp_size != vmi_read(vmi, &ctx, &(buf64[4]), sp_size) )
                goto exit;
    }

    
        //printf(" Arguments: %" PRIu32 "\n", 6);


    if ( 4 == reg_size ){
        ctx.addr = buf32[5];
        vmi_read(vmi, &ctx, &buf32[5], 32);

        
        if ((buf32[5]&0xF0)==0){
            goto exit;
        }


        printf("Size_Addr: 0x%" PRIx32, buf32[3]);
        ctx.addr = buf32[3];
        if(VMI_SUCCESS != vmi_read_32(vmi, &ctx, &buf32[3])){
            printf("ERROR\n");
        }

        printf(" Size: 0x%" PRIx32, buf32[3]);


        printf(" Protect: 0x%" PRIx32, buf32[5]);

    }else{
        //printf("0x%" PRIx64, buf64[i]);
    }
    printf("\n");

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
    p->first_cb_trap.cb = first_cb;
    p->first_cb_trap.data = p;

    p->ntpvm_cb_trap.breakpoint.lookup_type = LOOKUP_PID;
    p->ntpvm_cb_trap.breakpoint.pid = 4;
    p->ntpvm_cb_trap.breakpoint.addr_type = ADDR_RVA;
    p->ntpvm_cb_trap.breakpoint.module = "ntoskrnl.exe";
    p->ntpvm_cb_trap.name = "NtProtectVirtualMemory";
    p->ntpvm_cb_trap.type = BREAKPOINT;
    p->ntpvm_cb_trap.cb = ntpvm_cb;
    p->ntpvm_cb_trap.data = p;

    p->thrd_cb_trap.breakpoint.lookup_type = LOOKUP_PID;
    p->thrd_cb_trap.breakpoint.pid = 4;
    p->thrd_cb_trap.breakpoint.addr_type = ADDR_RVA;
    p->thrd_cb_trap.breakpoint.module = "ntoskrnl.exe";
    p->thrd_cb_trap.name = "NtMapViewOfSection";
    p->thrd_cb_trap.type = BREAKPOINT;
    p->thrd_cb_trap.cb = thrd_cb;
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

