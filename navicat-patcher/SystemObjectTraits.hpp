#pragma once
#include <unistd.h>
#include <sys/mman.h>

struct FileHandleTraits {
    using HandleType = int;
    static inline const HandleType InvalidValue = -1;
    static constexpr auto& Releasor = close;
};

struct MapViewTraits {

    struct HandleType {
        void* _Ptr;
        size_t _Size;

        bool operator==(const HandleType& Other) const noexcept {
            if (_Ptr == MAP_FAILED && Other._Ptr == MAP_FAILED)
                return true;
            else
                return _Ptr == Other._Ptr && _Size == Other._Size;
        }

        bool operator!=(const HandleType& Other) const noexcept {
            return !(*this == Other);
        }

        operator void*() const noexcept {
            return _Ptr;
        }

        template<typename __Type>
        __Type* View() const noexcept {

            return reinterpret_cast<__Type*>(_Ptr);
        }

        template<typename __Type>
        const __Type* ConstView() const noexcept {
            return reinterpret_cast<__Type*>(_Ptr);
        }

        template<typename __Type>
        __Type* ViewAtOffset(size_t Offset) const noexcept {
            return reinterpret_cast<__Type*>(reinterpret_cast<char*>(_Ptr) + Offset);
        }

        template<typename __Type>
        const __Type* ConstViewAtOffset(size_t Offset) const noexcept {
            return reinterpret_cast<__Type*>(reinterpret_cast<char*>(_Ptr) + Offset);
        }

        size_t Size() const noexcept {
            return _Size;
        }
    };

    static inline const HandleType InvalidValue = { MAP_FAILED, 0 };

    static inline void Releasor(const HandleType& RefHandle) {
        munmap(RefHandle._Ptr, RefHandle._Size);
    };
};

