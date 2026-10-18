#include "CredentialFactory.h"
#include "WebCredential.h"
#include "WiFiCredential.h"
#include "SSHCredential.h"
#include "VaultExceptions.h"
#include <istream>
std::shared_ptr<Credential> CredentialFactory::create(const std::string&t){if(t=="generic")return std::make_shared<Credential>();if(t=="web")return std::make_shared<WebCredential>();if(t=="wifi")return std::make_shared<WiFiCredential>();if(t=="ssh")return std::make_shared<SSHCredential>();throw CorruptedVaultException("Unknown credential type: "+t);}
std::shared_ptr<Credential> CredentialFactory::deserialize(const std::string&t,std::istream&i){auto c=create(t);c->deserialize(i);if(!i)throw CorruptedVaultException("Invalid credential data");return c;}
