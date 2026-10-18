#ifndef REPOSITORY_H
#define REPOSITORY_H

#include <algorithm>
#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

/**
 * @brief Generic in-memory repository managing collections of shared objects.
 *
 * Provides storage, retrieval, replacement, search, and iteration
 * for dynamically allocated elements of type T managed by std::shared_ptr.
 *
 * @tparam T The element type stored within the repository.
 */
template <typename T>
class Repository {
private:
    std::vector<std::shared_ptr<T>> items;

public:
    using iterator = typename std::vector<std::shared_ptr<T>>::iterator;
    using const_iterator = typename std::vector<std::shared_ptr<T>>::const_iterator;

    /**
     * @brief Default constructor creating an empty repository.
     */
    Repository() = default;

    /**
     * @brief Adds a new item to the repository.
     * @param item Shared pointer to the element to add. Null pointers are ignored.
     */
    void add(std::shared_ptr<T> item) {
        if (item) {
            items.push_back(std::move(item));
        }
    }

    /**
     * @brief Removes the item at the specified index.
     * @param index The zero-based index of the item to remove.
     * @return True if the item was removed; false if index is out of bounds.
     */
    bool remove(size_t index) {
        if (index >= items.size()) {
            return false;
        }
        items.erase(items.begin() + index);
        return true;
    }

    /**
     * @brief Removes the first occurrence of the specified item by pointer equality.
     * @param item Shared pointer to the item to remove.
     * @return True if the item was found and removed; false otherwise.
     */
    bool remove(const std::shared_ptr<T>& item) {
        auto iter = std::find(items.begin(), items.end(), item);
        if (iter == items.end()) {
            return false;
        }
        items.erase(iter);
        return true;
    }

    /**
     * @brief Retrieves the item at the specified index.
     * @param index The zero-based index of the item.
     * @return Shared pointer to the item, or nullptr if index is out of bounds.
     */
    std::shared_ptr<T> get(size_t index) const {
        if (index >= items.size()) {
            return nullptr;
        }
        return items[index];
    }

    /**
     * @brief Replaces the item at the specified index with a new item.
     * @param index The zero-based index of the item to replace.
     * @param item Shared pointer to the replacement item.
     * @return True if replacement succeeded; false if index is invalid or item is null.
     */
    bool replace(size_t index, std::shared_ptr<T> item) {
        if (index >= items.size() || !item) {
            return false;
        }
        items[index] = std::move(item);
        return true;
    }

    /**
     * @brief Retrieves a const reference to all items in the repository.
     * @return Const reference to vector of shared pointers.
     */
    const std::vector<std::shared_ptr<T>>& getAll() const {
        return items;
    }

    /**
     * @brief Finds all items matching a given predicate function.
     * @tparam Predicate Callable type accepting const T& and returning bool.
     * @param predicate The condition to test each element against.
     * @return Vector of shared pointers to all matching elements.
     */
    template <typename Predicate>
    std::vector<std::shared_ptr<T>> find(Predicate predicate) const {
        std::vector<std::shared_ptr<T>> result;
        for (const auto& item : items) {
            if (item && predicate(*item)) {
                result.push_back(item);
            }
        }
        return result;
    }

    /**
     * @brief Returns the number of items stored in the repository.
     * @return Count of elements.
     */
    size_t size() const {
        return items.size();
    }

    /**
     * @brief Clears all items from the repository.
     */
    void clear() {
        items.clear();
    }

    /**
     * @brief Returns an iterator to the beginning of the repository collection.
     * @return Iterator to the first element.
     */
    iterator begin() {
        return items.begin();
    }

    /**
     * @brief Returns an iterator to the end of the repository collection.
     * @return Iterator to the end.
     */
    iterator end() {
        return items.end();
    }

    /**
     * @brief Returns a const iterator to the beginning of the repository collection.
     * @return Const iterator to the first element.
     */
    const_iterator begin() const {
        return items.begin();
    }

    /**
     * @brief Returns a const iterator to the end of the repository collection.
     * @return Const iterator to the end.
     */
    const_iterator end() const {
        return items.end();
    }
};

#endif // REPOSITORY_H
