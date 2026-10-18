#pragma once
#include "IVault.h"
#include "Vault.h"
class VaultProxy:public IVault {
    Vault& vault; bool authenticated;
    void authorize()const;
public:
    explicit VaultProxy(Vault& v,bool authenticated=false):vault(v),authenticated(authenticated){}
    void setAuthenticated(bool value){authenticated=value;} void addCredential(std::shared_ptr<Credential>)override; bool updateCredential(size_t,std::shared_ptr<Credential>)override; bool deleteCredential(size_t)override;
    std::vector<std::shared_ptr<Credential>> getCredentials()const override; std::vector<std::shared_ptr<Credential>> search(const std::string&)const override; void lock()override; bool isLocked()const override;
};
