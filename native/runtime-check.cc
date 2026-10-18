// Integration-only compatibility probe. Never copied into the production image.
#include <expat.h>
#include <iconv.h>
#include <cstring>
#include <iostream>
#include <ft2build.h>
#include FT_FREETYPE_H
#include <zlib.h>
#include <new>
#ifndef _LIBCPP_VERSION
#error The musl runtime requires LLVM libc++
#endif
int main() {
 if(std::strcmp(XML_ExpatVersion(),"expat_2.9.0"))return 1;
 // Poppler uses iconv for its public UTF-16 string API. Check the built-in musl Unicode conversions.
 for(const char* encoding:{"UTF-16LE","UTF-16BE","UTF-32LE","UTF-32BE"}) {
  iconv_t codec=iconv_open("UTF-8",encoding);if(codec==reinterpret_cast<iconv_t>(-1))return 2;
  iconv_close(codec);
 }
 const char* text="<fontconfig><dir>/usr/share/fonts</dir></fontconfig>";
 XML_Parser parser=XML_ParserCreate(nullptr);if(!parser)return 3;
 int result=XML_Parse(parser,text,std::strlen(text),XML_TRUE);
 XML_ParserFree(parser);if(result!=XML_STATUS_OK)return 4;
 if(std::strcmp(zlibVersion(),"1.3.2"))return 5;
 FT_Library fonts=nullptr;if(FT_Init_FreeType(&fonts))return 6;
 int major=0,minor=0,patch=0;FT_Library_Version(fonts,&major,&minor,&patch);
 if(major!=2||minor!=14||patch!=3)return 7;
 FT_Face face=nullptr;
 if(FT_New_Face(fonts,"/usr/share/fonts/dejavu/DejaVuSans.ttf",0,&face))return 8;
 if(FT_Load_Char(face,'A',FT_LOAD_DEFAULT))return 9;
 FT_Done_Face(face);FT_Done_FreeType(fonts);
 // Ordinary compression round trip through the actual replacement library.
 unsigned char compressed[256],plain[256];uLongf clen=sizeof compressed,plen=sizeof plain;
 const unsigned char message[]="normal compressed PDF stream";
 if(compress(compressed,&clen,message,sizeof message)!=Z_OK||uncompress(plain,&plen,compressed,clen)!=Z_OK||plen!=sizeof message||std::memcmp(plain,message,plen))return 10;
 struct alignas(64) Aligned { char bytes[64]; }; auto* aligned=new Aligned{};delete aligned;
 std::cout<<"FreeType 2.14.3; zlib 1.3.2; "<<XML_ExpatVersion()<<"; Unicode codecs and trusted font XML OK\n";
}
