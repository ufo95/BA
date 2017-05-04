#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libinjector/libinjector.h>
#include "packeranalyser.h"



packeranalyser::packeranalyser(drakvuf_t drakvuf, const void *config, output_format_t output){
	int pid = 0;
	pid = injector_start_app(drakvuf, 1144, 0, "C:\\Windows\\System32\\Notepad123321.exe");
	printf("Hellooo! PID: %i\n", pid);
}

packeranalyser::~packeranalyser() {
	printf("Goodbye!\n");
}