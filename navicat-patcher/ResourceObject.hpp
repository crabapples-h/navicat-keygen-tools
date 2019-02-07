#pragma once
#include <type_traits>

template<typename __ResourceTraits>
class ResourceObject {
public:
    using HandleType = typename __ResourceTraits::HandleType;
    static inline const HandleType& InvalidValue = __ResourceTraits::InvalidValue;
protected:
    HandleType _$_Handle;
public:

    ResourceObject() noexcept :
        _$_Handle(InvalidValue) {}

    ResourceObject(const HandleType& Handle) noexcept :
        _$_Handle(Handle) {}

    ResourceObject(const ResourceObject<__ResourceTraits>&) = delete;

    ResourceObject(ResourceObject<__ResourceTraits>&& Other) noexcept :
        _$_Handle(Other._$_Handle)
    {
        Other._$_Handle = InvalidValue;
    }

    ResourceObject<__ResourceTraits>&
    operator=(const ResourceObject<__ResourceTraits>& Other) = delete;

    ResourceObject<__ResourceTraits>&
    operator=(ResourceObject<__ResourceTraits>&& Other) noexcept {
        _$_Handle = Other._$_Handle;
        Other._$_Handle = InvalidValue;
        return *this;
    }

    template<typename __DummyType = int,
             typename = typename std::enable_if<std::is_pointer<HandleType>::value, __DummyType>::type>
    HandleType operator->() const noexcept {
        return _$_Handle;
    }

    operator HandleType() const noexcept {
        return _$_Handle;
    }

    // Check if handle is a valid handle
    bool IsValid() const noexcept {
        return _$_Handle != InvalidValue;
    }

    HandleType RetrieveHandle() const noexcept {
        return _$_Handle;
    }

    void Abandon() noexcept {
        _$_Handle = InvalidValue;
    }

    void TakeOver(const HandleType& Handle) {
        if (_$_Handle != InvalidValue)
            Release();
        _$_Handle = Handle;
    }

    // Force release
    void Release() {
        if (_$_Handle != InvalidValue) {
            __ResourceTraits::Releasor(_$_Handle);
            _$_Handle = InvalidValue;
        }
    }

    ~ResourceObject() {
        Release();
    }
};

template<typename __ClassType>
struct CppObjectTraits {
    using HandleType = __ClassType*;
    static inline const HandleType InvalidValue = nullptr;
    static inline void Releasor(HandleType pObject) {
        delete pObject;
    }
};

template<typename __ClassType>
struct CppDynamicArrayTraits {
    using HandleType = __ClassType*;
    static inline const HandleType InvalidValue = nullptr;
    static inline void Releasor(HandleType pArray) {
        delete[] pArray;
    }
};

