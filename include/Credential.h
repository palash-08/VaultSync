#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <string>
using namespace std;
class Credential{
protected:
    string username;
    string password;
    string notes;

public:
    Credential(const string& username,
               const string& password,
               const string& notes);
};

#endif
