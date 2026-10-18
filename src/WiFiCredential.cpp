#include "WiFiCredential.h"
#include <iostream>
namespace {void put(std::ostream&o,const std::string&s){uint32_t n=s.size();o.write((char*)&n,4);o.write(s.data(),n);}std::string get(std::istream&i){uint32_t n=0;i.read((char*)&n,4);if(!i||n>16*1024*1024){i.setstate(std::ios::failbit);return{};}std::string s(n,'\0');if(n)i.read(&s[0],n);return s;}}
WiFiCredential::WiFiCredential(const std::string&s,const std::string&u,const std::string&p,const std::string&n,const std::string&ssid_,const std::string&sec):Credential(s,u,p,n),ssid(ssid_),securityType(sec){}
std::string WiFiCredential::getType()const{return "wifi";}const std::string&WiFiCredential::getSsid()const{return ssid;}const std::string&WiFiCredential::getSecurityType()const{return securityType;}
void WiFiCredential::display(bool show)const{Credential::display(show);std::cout<<"SSID: "<<ssid<<"\nSecurity: "<<securityType<<"\n";}Credential*WiFiCredential::clone()const{return new WiFiCredential(*this);}
void WiFiCredential::serialize(std::ostream&o)const{Credential::serialize(o);put(o,ssid);put(o,securityType);}void WiFiCredential::deserialize(std::istream&i){Credential::deserialize(i);ssid=get(i);securityType=get(i);}bool WiFiCredential::matches(const std::string&q)const{return Credential::matches(q)||ssid.find(q)!=std::string::npos;}
