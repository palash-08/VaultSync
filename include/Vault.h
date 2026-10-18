#pragma once
#include "IVault.h"
#include "Repository.h"
class Vault:public IVault {
    Repository<Credential> credentials; bool locked=false;
public:
    void addCredential(std::shared_ptr<Credential>)override; bool updateCredential(size_t,std::shared_ptr<Credential>)override; bool deleteCredential(size_t)override;
    std::vector<std::shared_ptr<Credential>> getCredentials()const override; std::vector<std::shared_ptr<Credential>> search(const std::string&)const override;
    void lock()override; bool isLocked()const override; void unlock();
};
