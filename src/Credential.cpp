#include "Credential.h"
using namespace std;
Credential::Credential(const string& username,
                       const string& password,
                       const string& notes)
    : username(username),
      password(password),
      notes(notes)
{
}
