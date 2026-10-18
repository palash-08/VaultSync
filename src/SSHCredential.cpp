#include "SSHCredential.h"
#include <iostream>
SSHCredential::SSHCredential(const std::string&s,const std::string&u,const std::string&p,const std::string&n,const std::string&h,uint16_t pt):Credential(s,u,p,n),host(h),port(pt){}
std::string SSHCredential::getType()const{return "ssh";}const std::string&SSHCredential::getHost()const{return host;}uint16_t SSHCredential::getPort()const{return port;}
void SSHCredential::display(bool show)const{Credential::display(show);std::cout<<"Host: "<<host<<"\nPort: "<<port<<"\n";}Credential*SSHCredential::clone()const{return new SSHCredential(*this);}
void SSHCredential::serialize(std::ostream&o)const{Credential::serialize(o);uint32_t n=host.size();o.write((char*)&n,4);o.write(host.data(),n);o.write((char*)&port,sizeof(port));}void SSHCredential::deserialize(std::istream&i){Credential::deserialize(i);uint32_t n=0;i.read((char*)&n,4);if(n>16*1024*1024){i.setstate(std::ios::failbit);return;}host.assign(n,'\0');if(n)i.read(&host[0],n);i.read((char*)&port,sizeof(port));}bool SSHCredential::matches(const std::string&q)const{return Credential::matches(q)||host.find(q)!=std::string::npos;}
