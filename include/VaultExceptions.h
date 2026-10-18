#pragma once
#include <stdexcept>
#include <string>
class VaultException:public std::runtime_error{public:explicit VaultException(const std::string&m):runtime_error(m){}};
class WrongPasswordException:public VaultException{public:explicit WrongPasswordException(const std::string&m="Wrong password"):VaultException(m){}};
class UnauthorizedAccessException:public VaultException{public:explicit UnauthorizedAccessException(const std::string&m="Vault access is not authorized"):VaultException(m){}};
class CorruptedVaultException:public VaultException{public:explicit CorruptedVaultException(const std::string&m="Vault data is corrupted"):VaultException(m){}};
class FileException:public VaultException{public:explicit FileException(const std::string&m="Vault file operation failed"):VaultException(m){}};
class LockoutException:public VaultException{public:explicit LockoutException(const std::string&m="Access is locked out"):VaultException(m){}};
