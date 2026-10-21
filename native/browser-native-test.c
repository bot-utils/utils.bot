// Synthetic regression checks. This executable is not shipped in the worker.
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *replace_path, *victim_path;
static int inject_race;

// Force GIO's fallback path, then deterministically insert an attacker symlink
// between unlink and open. The original library opens the symlink target;
// the patched library must return an error and leave the victim untouched.
int g_mkstemp_full(char *template, int flags, int mode) {
 (void)template;(void)flags;(void)mode;errno=EACCES;return -1;
}
int unlink(const char *path) {
 int (*real_unlink)(const char *)=dlsym(RTLD_NEXT,"unlink");assert(real_unlink);
 int result=real_unlink(path);
 if(!result && inject_race && !strcmp(path,replace_path))assert(!symlink(victim_path,replace_path));
 return result;
}

static void write_file(const char *path,const char *text) {
 FILE *file=fopen(path,"w");assert(file);assert(fputs(text,file)>=0);assert(!fclose(file));
}
static void gio_race_test(void) {
 void *gio=dlopen("libgio-2.0.so.0",RTLD_NOW|RTLD_LOCAL);assert(gio);
 void *(*file_new)(const char *)=dlsym(gio,"g_file_new_for_path");assert(file_new);
 void *(*replace)(void *,const char *,int,int,void *,void **)=dlsym(gio,"g_file_replace");assert(replace);
 ssize_t (*write_stream)(void *,const void *,size_t,void *,void **)=dlsym(gio,"g_output_stream_write");assert(write_stream);
 int (*close_stream)(void *,void *,void **)=dlsym(gio,"g_output_stream_close");assert(close_stream);
 void (*unref)(void *)=dlsym(gio,"g_object_unref");assert(unref);
 void (*free_error)(void *)=dlsym(gio,"g_error_free");assert(free_error);
 char directory[]="/tmp/native-gio-XXXXXX",path[256],victim[256];assert(mkdtemp(directory));
 assert(snprintf(path,sizeof path,"%s/replace",directory)>0);
 assert(snprintf(victim,sizeof victim,"%s/victim",directory)>0);
 replace_path=path;victim_path=victim;
 write_file(path,"original");write_file(victim,"protected");
 void *file=file_new(path),*error=NULL;
 void *stream=replace(file,NULL,0,2,NULL,&error);assert(stream && !error);
 assert(write_stream(stream,"normal",6,NULL,&error)==6);assert(close_stream(stream,NULL,&error));unref(stream);
 inject_race=1;
 stream=replace(file,NULL,0,2,NULL,&error);
 assert(!stream && error);free_error(error);inject_race=0;unref(file);
 FILE *guard=fopen(victim,"r");assert(guard);char text[32]={0};assert(fread(text,1,sizeof text-1,guard)==9);fclose(guard);
 assert(!strcmp(text,"protected"));
 puts("gio_symlink_race_rejected");
}

static void *symbol(void *library, const char *name) {
 void *result=dlsym(library,name);
 assert(result);
 return result;
}
int main(void) {
 alarm(5); // A negative CRC length used to loop indefinitely.
 const char *(*libc_version)(void)=symbol(RTLD_DEFAULT,"gnu_get_libc_version");
 assert(!strcmp(libc_version(),"2.43"));
 void *z=dlopen("libz.so.1",RTLD_NOW|RTLD_LOCAL);assert(z);
 const char *(*zversion)(void)=symbol(z,"zlibVersion");
 unsigned long (*combine)(int64_t)=symbol(z,"crc32_combine_gen64");
 assert(!strcmp(zversion(),"1.3.2"));
 assert(!dlsym(z,"zipOpenNewFileInZip4_64"));
 assert(combine(-1)==0);assert(combine(INT64_MIN)==0);
 void *sql=dlopen("libsqlite3.so.0",RTLD_NOW|RTLD_LOCAL);assert(sql);
 int (*sqlversion)(void)=symbol(sql,"sqlite3_libversion_number");
 assert(sqlversion()==3053004);
 void *alsa=dlopen("libasound.so.2",RTLD_NOW|RTLD_LOCAL);assert(alsa);
 int (*alloc)(void **)=symbol(alsa,"snd_ctl_elem_id_malloc");
 void (*release)(void *)=symbol(alsa,"snd_ctl_elem_id_free");
 int (*parse)(void *,const char *)=symbol(alsa,"snd_ctl_ascii_elem_id_parse");
 const char *(*name)(const void *)=symbol(alsa,"snd_ctl_elem_id_get_name");
 void *id=NULL;assert(!alloc(&id));
 // CVE-2026-90781: exactly 64 bytes used to overrun a stack buffer by one.
 char text[512];memset(text,'A',sizeof text);memcpy(text,"name=",5);text[69]=0;
 assert(!parse(id,text));assert(strlen(name(id))<=63);
 memset(text+5,'A',sizeof text-5);text[sizeof text-1]=0;
 assert(!parse(id,text));assert(strlen(name(id))<=63);release(id);
 // The separately vulnerable topology decoder is not built or shipped.
 assert(!dlopen("libatopology.so.2",RTLD_NOW|RTLD_LOCAL));
 gio_race_test();
 write_file("/tmp/native-regressions-passed","native_regressions_passed\n");
 puts("native_regressions_passed");
 return 0;
}
