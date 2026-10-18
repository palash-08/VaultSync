#pragma once
#include "Credential.h"
#include <memory>
#include <string>
#include <vector>
class IVault { public: virtual ~IVault()=default; virtual void addCredential(std::shared_ptr<Credential>)=0; virtual bool updateCredential(size_t,std::shared_ptr<Credential>)=0; virtual bool deleteCredential(size_t)=0; virtual std::vector<std::shared_ptr<Credential>> getCredentials()const=0; virtual std::vector<std::shared_ptr<Credential>> search(const std::string&)const=0; virtual void lock()=0; virtual bool isLocked()const=0; };
