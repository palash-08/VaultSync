#include "PasswordGenerator.h"
#include <algorithm>
#include <random>
#include <stdexcept>
std::string PasswordGenerator::generate(const PasswordOptions&o){std::string pool,required;if(o.uppercase){pool+="ABCDEFGHIJKLMNOPQRSTUVWXYZ";required+='A';}if(o.lowercase){pool+="abcdefghijklmnopqrstuvwxyz";required+='a';}if(o.digits){pool+="0123456789";required+='0';}if(o.symbols){pool+="!@#$%^&*()-_=+[]{};:,.?";required+='!';}if(pool.empty()||o.length<required.size())throw std::invalid_argument("Password options cannot satisfy requested length");std::random_device rd;std::mt19937 gen(rd());std::uniform_int_distribution<size_t>d(0,pool.size()-1);std::string out=required;while(out.size()<o.length)out+=pool[d(gen)];std::shuffle(out.begin(),out.end(),gen);return out;}
std::string PasswordGenerator::generate(size_t n,bool u,bool l,bool d,bool s){return generate(PasswordOptions{n,u,l,d,s});}
