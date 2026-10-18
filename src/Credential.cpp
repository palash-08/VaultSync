#include "Credential.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <limits>
#include <chrono>
#include "WebCredential.h"
#include "WiFiCredential.h"
#include "SSHCredential.h"

namespace {
void put(std::ostream& o, const std::string& s) { uint32_t n=static_cast<uint32_t>(s.size()); o.write(reinterpret_cast<const char*>(&n),4); o.write(s.data(),n); }
std::string get(std::istream& i) { uint32_t n=0; i.read(reinterpret_cast<char*>(&n),4); if(!i||n>16*1024*1024) { i.setstate(std::ios::failbit); return {}; } std::string s(n,'\0'); if(n)i.read(&s[0],n); return s; }
std::string lower(std::string s) { std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));}); return s; }
}
Credential::Credential(const std::string& s,const std::string& u,const std::string& p,const std::string& n,int64_t t):service(s),username(u),password(p),notes(n),createdAt(t<0?std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()):t){}
std::string Credential::getType() const { return "generic"; }
void Credential::display(bool show) const { std::cout<<"Service: "<<service<<"\nUsername: "<<username<<"\nPassword: "<<(show?password:"********")<<"\nNotes: "<<notes<<"\n"; }
Credential* Credential::clone() const { return new Credential(*this); }
void Credential::serialize(std::ostream& o) const { put(o,service);put(o,username);put(o,password);put(o,notes);o.write(reinterpret_cast<const char*>(&createdAt),sizeof(createdAt)); }
void Credential::deserialize(std::istream& i) { service=get(i);username=get(i);password=get(i);notes=get(i);i.read(reinterpret_cast<char*>(&createdAt),sizeof(createdAt)); }
bool Credential::matches(const std::string& q) const { auto x=lower(q); return lower(service).find(x)!=std::string::npos||lower(username).find(x)!=std::string::npos||lower(notes).find(x)!=std::string::npos; }
const std::string& Credential::getService()const{return service;} const std::string& Credential::getUsername()const{return username;} const std::string& Credential::getPassword()const{return password;} const std::string& Credential::getNotes()const{return notes;} int64_t Credential::getCreatedAt()const{return createdAt;}
void Credential::setService(const std::string& v){service=v;} void Credential::setUsername(const std::string& v){username=v;} void Credential::setPassword(const std::string& v){password=v;} void Credential::setNotes(const std::string& v){notes=v;}
bool Credential::operator==(const Credential& o)const{
    if(getType()!=o.getType()||service!=o.service||username!=o.username||password!=o.password||notes!=o.notes||createdAt!=o.createdAt)return false;
    if(auto a=dynamic_cast<const WebCredential*>(this)){auto b=dynamic_cast<const WebCredential*>(&o);return b&&a->getUrl()==b->getUrl();}
    if(auto a=dynamic_cast<const WiFiCredential*>(this)){auto b=dynamic_cast<const WiFiCredential*>(&o);return b&&a->getSsid()==b->getSsid()&&a->getSecurityType()==b->getSecurityType();}
    if(auto a=dynamic_cast<const SSHCredential*>(this)){auto b=dynamic_cast<const SSHCredential*>(&o);return b&&a->getHost()==b->getHost()&&a->getPort()==b->getPort();}
    return true;
}
bool Credential::operator!=(const Credential& o)const{return !(*this==o);} std::ostream& operator<<(std::ostream& o,const Credential& c){o<<"Credential("<<c.getType()<<", "<<c.service<<", "<<c.username<<")";return o;}
