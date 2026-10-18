#pragma once
#include <algorithm>
#include <memory>
#include <vector>
template<class T> class Repository {
    std::vector<std::shared_ptr<T>> items;
public:
    using iterator=typename std::vector<std::shared_ptr<T>>::iterator; using const_iterator=typename std::vector<std::shared_ptr<T>>::const_iterator;
    void add(std::shared_ptr<T> item){if(item)items.push_back(std::move(item));}
    bool remove(size_t i){if(i>=items.size())return false;items.erase(items.begin()+i);return true;}
    bool remove(const std::shared_ptr<T>& item){auto it=std::find(items.begin(),items.end(),item);if(it==items.end())return false;items.erase(it);return true;}
    std::shared_ptr<T> get(size_t i)const{return i<items.size()?items[i]:nullptr;}
    bool replace(size_t i,std::shared_ptr<T> item){if(i>=items.size()||!item)return false;items[i]=std::move(item);return true;}
    const std::vector<std::shared_ptr<T>>& getAll()const{return items;}
    template<class Predicate> std::vector<std::shared_ptr<T>> find(Predicate predicate)const{std::vector<std::shared_ptr<T>> result;for(auto&v:items)if(predicate(*v))result.push_back(v);return result;}
    size_t size()const{return items.size();} void clear(){items.clear();} iterator begin(){return items.begin();} iterator end(){return items.end();} const_iterator begin()const{return items.begin();} const_iterator end()const{return items.end();}
};
