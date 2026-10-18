#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <stdexcept>
#include <vector>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "warmup.inc"
#ifdef PDFIUM
#include "fpdfview.h"
#include "fpdf_text.h"
#else
#include <fontconfig/fontconfig.h>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#endif

static constexpr size_t maxInput=100*1024*1024, maxText=1024*1024;
static void limit(int what, rlim_t value) { rlimit r{value,value}; if(setrlimit(what,&r)) _exit(20); }
static void prepare() {
 limit(RLIMIT_AS,1024ULL*1024*1024); limit(RLIMIT_CPU,8); limit(RLIMIT_CORE,0); limit(RLIMIT_NOFILE,16);
 pid_t parent=getppid();
 if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent) _exit(20);
 if(prctl(PR_SET_DUMPABLE,0)) _exit(20);
 // exec already closed every unrelated descriptor; harden against inherited mistakes.
 if(syscall(SYS_close_range,3u,~0u,0)!=0) {
  // Go exec closes unrelated descriptors too; fail closed if the kernel cannot enforce this sweep.
  _exit(20);
 }
}

static void confine() {
 DIR* taskDir=opendir("/proc/self/task");if(!taskDir)_exit(20);
 int threads=0;while(auto* entry=readdir(taskDir)){if(entry->d_name[0]!='.')threads++;}
 closedir(taskDir);if(threads!=1)_exit(20);
 // Warmup may have opened descriptors after prepare(). Revoke every such
 // capability before customer syntax is loaded; required fonts stay mapped.
 if(syscall(SYS_close_range,3u,~0u,0)!=0)_exit(20);
#ifdef __aarch64__
 constexpr uint32_t arch=AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
 constexpr uint32_t arch=AUDIT_ARCH_X86_64;
#else
#error Unsupported syscall architecture
#endif
 std::vector<sock_filter> f;
 auto stmt=[&](uint16_t c,uint32_t k){f.push_back(BPF_STMT(c,k));};
 auto jump=[&](uint16_t c,uint32_t k,uint8_t a,uint8_t b){f.push_back(BPF_JUMP(c,k,a,b));};
 stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,arch));
 jump(BPF_JMP|BPF_JEQ|BPF_K,arch,1,0); stmt(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
 stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr));
 // musl probes terminal dimensions when initializing stdout. Refuse every
 // ioctl rather than granting device/descriptor control to document code.
 jump(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,0,1);stmt(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOTTY);
 // libc probes stdout with newfstatat; deny path metadata without killing benign stdio.
 jump(BPF_JMP|BPF_JEQ|BPF_K,SYS_newfstatat,0,1);stmt(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOENT);
 // Trusted loader initialization is complete; text extraction needs no JIT.
 // Deny creation of executable mappings after confinement, including W+X.
 for(int nr:{SYS_mmap,SYS_mprotect}) {
  jump(BPF_JMP|BPF_JEQ|BPF_K,nr,0,3);
  stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args)+2*sizeof(uint64_t));
  jump(BPF_JMP|BPF_JSET|BPF_K,PROT_EXEC,0,1);
  stmt(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
  stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr));
 }
 // Narrow allowlist: no open/socket/clone/exec/kill/ptrace/process_vm/io_uring.
 // musl writes buffered stdout with writev. It has only the same three stdio
 // descriptors as write; confinement cannot open or inherit another capability.
 const int allowed[]={SYS_read,SYS_write,SYS_writev,SYS_close,SYS_fstat,SYS_lseek,SYS_brk,SYS_mmap,SYS_munmap,
 SYS_mprotect,SYS_mremap,SYS_madvise,SYS_futex,SYS_clock_gettime,SYS_gettimeofday,SYS_getrandom,
 SYS_getpid,SYS_gettid,SYS_rt_sigaction,SYS_rt_sigprocmask,SYS_rt_sigreturn,SYS_sched_yield,SYS_exit,SYS_exit_group};
 for(int nr:allowed){jump(BPF_JMP|BPF_JEQ|BPF_K,nr,0,1);stmt(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);}
 stmt(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
 sock_fprog prog{static_cast<unsigned short>(f.size()),f.data()};
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog)) _exit(20);
}

static std::string quote(const std::string& text) {
 std::string out="\""; out.reserve(text.size()+2);
 static const char hex[]="0123456789abcdef";
 for(unsigned char c:text){
  if(c=='"'||c=='\\'){out+='\\';out+=c;}
  else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
  else out+=c;
 }
 out+='"';return out;
}
static void clip(std::string& text,size_t cap) {
 if(text.size()<=cap)return;
 size_t n=cap;while(n>0 && (static_cast<unsigned char>(text[n])&0xc0)==0x80)n--;
 text.resize(n);
}
#ifdef PDFIUM
static std::string utf8(const std::vector<unsigned short>& text,int count) {
 if(count<0 || static_cast<size_t>(count)>text.size())throw std::out_of_range("text count");
 std::string out;
 for(int i=0;i<count;i++) {
  uint32_t c=text[i]; if(!c)continue;
  if(c>=0xd800 && c<=0xdbff && i+1<count && text[i+1]>=0xdc00 && text[i+1]<=0xdfff) c=0x10000+((c-0xd800)<<10)+(text[++i]-0xdc00);
  else if(c>=0xd800 && c<=0xdfff)c=0xfffd;
  if(c<0x80)out+=char(c);
  else if(c<0x800){out+=char(0xc0|(c>>6));out+=char(0x80|(c&63));}
  else if(c<0x10000){out+=char(0xe0|(c>>12));out+=char(0x80|((c>>6)&63));out+=char(0x80|(c&63));}
  else {out+=char(0xf0|(c>>18));out+=char(0x80|((c>>12)&63));out+=char(0x80|((c>>6)&63));out+=char(0x80|(c&63));}
 }
 return out;
}
#endif

int main() {
 prepare();
 std::vector<char> data;data.reserve(1024*1024);
 char chunk[65536];ssize_t n;
 while((n=read(0,chunk,sizeof chunk))>0){if(data.size()+n>maxInput)return 21;data.insert(data.end(),chunk,chunk+n);}
 if(n<0 || data.empty())return 21;
#ifdef PDFIUM
 FPDF_LIBRARY_CONFIG config{};config.version=2; // No JS platform, V8 isolate or XFA execution.
 FPDF_InitLibraryWithConfig(&config);
 auto warmDoc=FPDF_LoadMemDocument64(warmupPDF,sizeof warmupPDF,nullptr);
 if(!warmDoc)return 20;
 auto warmPage=FPDF_LoadPage(warmDoc,0);if(!warmPage)return 20;
 auto warmText=FPDFText_LoadPage(warmPage);if(!warmText)return 20;
 (void)FPDFText_CountChars(warmText);
#else
 if(!FcInit())return 20;
 auto warm=poppler::ustring::from_utf8("warmup").to_utf8();(void)warm;
 std::unique_ptr<poppler::document> warmDoc(poppler::document::load_from_raw_data(reinterpret_cast<const char*>(warmupPDF),sizeof warmupPDF));
 if(!warmDoc)return 20;
 std::unique_ptr<poppler::page> warmPage(warmDoc->create_page(0));if(!warmPage)return 20;
 auto warmText=warmPage->text().to_utf8();(void)warmText;
#endif
#ifdef PDF_WORKER_TEST
 int warmDescriptor=-1;
 if(const char* mode=getenv("WORKER_TEST");mode && !strcmp(mode,"warm_descriptor")) {
  warmDescriptor=syscall(SYS_openat,AT_FDCWD,"/opt/pdfium/LICENSE",0);
  if(warmDescriptor<3)return 31;
 }
#endif
 confine(); // No customer PDF syntax may be loaded before this point.
#ifdef PDF_WORKER_TEST
 // Controlled sandbox fixtures, never selected by customer content or deployed server routes.
 const char* mode=getenv("WORKER_TEST");
 if(mode && !strcmp(mode,"warm_descriptor")){
  char byte;errno=0;if(read(warmDescriptor,&byte,1)!=-1 || errno!=EBADF)return 31;
  std::cout<<"warm_descriptor_closed";std::cout.flush();_exit(0);
 }
 if(mode && !strcmp(mode,"text_bounds")){
  bool bounded=false;try{(void)utf8(std::vector<unsigned short>{'A'},2);}catch(const std::out_of_range&){bounded=true;}
  if(!bounded)return 31;std::cout<<"text_count_bounded";std::cout.flush();_exit(0);
 }
 if(mode && !strcmp(mode,"spin")){for(;;)asm volatile("");}
 if(mode && !strcmp(mode,"ioctl")){
  unsigned long value=0x12345678;
  for(unsigned long request:{0x5413UL,0x5421UL,~0UL}){
   errno=0;if(syscall(SYS_ioctl,1,request,&value)!=-1 || errno!=ENOTTY || value!=0x12345678)return 31;
  }
  std::cout<<"ioctl_denied";std::cout.flush();_exit(0);
 }
 if(mode && !strcmp(mode,"signal")){syscall(SYS_kill,getppid(),SIGKILL);return 30;}
 if(mode && !strcmp(mode,"map_exec")){mmap(nullptr,4096,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);return 30;}
 if(mode && !strcmp(mode,"protect_exec")){void* p=mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 31;mprotect(p,4096,PROT_READ|PROT_EXEC);return 30;}
 if(mode && !strcmp(mode,"open")){syscall(SYS_openat,AT_FDCWD,"/proc/self/environ",0);return 30;}
 if(mode && !strcmp(mode,"flood")){for(;;)write(1,chunk,sizeof chunk);}
#endif
 try {
#ifdef PDFIUM
 auto document=FPDF_LoadMemDocument64(data.data(),data.size(),nullptr);
 if(!document){return FPDF_GetLastError()==FPDF_ERR_PASSWORD?13:12;}
 int count=FPDF_GetPageCount(document);
#else
 std::unique_ptr<poppler::document> document(poppler::document::load_from_raw_data(data.data(),static_cast<int>(data.size())));
 if(!document)return 12;
 if(document->is_locked())return 13;
 int count=document->pages();
#endif
 if(count<0)return 12;
 bool truncated=count>100;size_t total=0;std::string pages="[";
 for(int i=0;i<std::min(count,100);i++) {
  double width=0,height=0;std::string text;
#ifdef PDFIUM
  FPDF_PAGE page=FPDF_LoadPage(document,i);if(!page)return 12;
  width=FPDF_GetPageWidth(page);height=FPDF_GetPageHeight(page);
  FPDF_TEXTPAGE tp=FPDFText_LoadPage(page);if(!tp)return 12;
  int chars=FPDFText_CountChars(tp);if(chars<0)return 12;
  int take=std::min(chars,static_cast<int>(maxText-total));
  std::vector<unsigned short> utf16(take+1);
  int got=take?FPDFText_GetText(tp,0,take,utf16.data()):0;
  text=utf8(utf16,std::max(0,got));if(take<chars)truncated=true;
  FPDFText_ClosePage(tp);FPDF_ClosePage(page);
#else
  std::unique_ptr<poppler::page> page(document->create_page(i));if(!page)return 12;
  auto rect=page->page_rect();width=rect.width();height=rect.height();
  auto raw=page->text().to_utf8();text.assign(raw.begin(),raw.end());
#endif
  if(!std::isfinite(width)||!std::isfinite(height)||width<0||height<0)return 12;
  if(text.size()>maxText-total)truncated=true;
  clip(text,maxText-total);total+=text.size();
  if(i)pages+=",";
  pages+="{\"index\":"+std::to_string(i)+",\"width\":"+std::to_string(width)+",\"height\":"+std::to_string(height)+",\"text\":"+quote(text)+"}";
  if(total>=maxText){truncated=true;break;}
 }
 pages+="]";
 std::cout<<"{\"pageCount\":"<<count<<",\"truncated\":"<<(truncated?"true":"false")<<",\"pages\":"<<pages<<"}";
 std::cout.flush();
 // _exit avoids teardown opening resources after successful extraction.
 _exit(0);
 }catch(...){_exit(12);}
}
