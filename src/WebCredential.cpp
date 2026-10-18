#include "WebCredential.h"
#include <iostream>
WebCredential::WebCredential(const std::string&s,const std::string&u,const std::string&p,const std::string&n,const std::string&v):Credential(s,u,p,n),url(v){}
std::string WebCredential::getType()const{return "web";} const std::string& WebCredential::getUrl()const{return url;} const std::string& WebCredential::getWebsite()const{return url;} void WebCredential::setUrl(const std::string&v){url=v;}
void WebCredential::display(bool show)const{Credential::display(show);std::cout<<"URL: "<<url<<"\n";} Credential* WebCredential::clone()const{return new WebCredential(*this);}
void WebCredential::serialize(std::ostream&o)const{Credential::serialize(o);uint32_t n=url.size();o.write((char*)&n,4);o.write(url.data(),n);} void WebCredential::deserialize(std::istream&i){Credential::deserialize(i);uint32_t n=0;i.read((char*)&n,4);if(n>16*1024*1024){i.setstate(std::ios::failbit);return;}url.assign(n,'\0');if(n)i.read(&url[0],n);}
bool WebCredential::matches(const std::string&q)const{return Credential::matches(q)||url.find(q)!=std::string::npos;}
