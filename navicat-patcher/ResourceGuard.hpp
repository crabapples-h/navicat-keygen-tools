#pragma once

template<typename __ResourceTraits>
class ResourceGuard {
private:
    using HandleType = typename __ResourceTraits::HandleType;
    HandleType _Handle;
    bool _DismissFlag;
public:

    ResourceGuard() noexcept :
        _Handle(__ResourceTraits::InvalidValue),
        _DismissFlag(false) {}

    explicit ResourceGuard(HandleType Handle) :
        _Handle(Handle),
        _DismissFlag(false) {}

    ResourceGuard(const ResourceGuard<__ResourceTraits>& Other) noexcept :
        _Handle(Other._Handle),
        _DismissFlag(false) {}

    ResourceGuard(ResourceGuard<__ResourceTraits>&& Other) noexcept :
        _Handle(Other._Handle),
        _DismissFlag(false) { Other._Handle = __ResourceTraits::InvalidValue; }

    ResourceGuard<__ResourceTraits>&
    operator=(const ResourceGuard<__ResourceTraits>& Other) noexcept {
        _Handle = Other._Handle;
        return *this;
    }

    ResourceGuard<__ResourceTraits>&
    operator=(ResourceGuard<__ResourceTraits>&& Other) noexcept {
        _Handle = Other._Handle;
        Other._Handle = __ResourceTraits::InvalidValue;
        return *this;
    }

    operator HandleType() const noexcept {
        return _Handle;
    }

    // Check if handle is a valid handle
    bool IsValid() const noexcept {
        return _Handle != __ResourceTraits::InvalidValue;
    }

    HandleType GetHandle() const noexcept {
        return _Handle;
    }

    // Abandon possession of the previous handle without any conditions
    // You must make sure that the previous handle has been released
    //   OR has been possessed by others
    void TakeHoldOf(HandleType Handle) noexcept {
        _Handle = Handle;
    }

    // If dismiss, the handle won't be released when ResourceGuard is destructed.
    void Dismiss() noexcept {
        _DismissFlag = true;
    }

    // Cancel Dismiss() operation
    void DismissCancel() noexcept {
        _DismissFlag = false;
    }

    // Force release
    void Release() {
        if (_Handle != __ResourceTraits::InvalidValue) {
            __ResourceTraits::Releasor(_Handle);
            _Handle = __ResourceTraits::InvalidValue;
        }
    }

    ~ResourceGuard() {
        if (!_DismissFlag && _Handle != __ResourceTraits::InvalidValue) {
            __ResourceTraits::Releasor(_Handle);
            _Handle = __ResourceTraits::InvalidValue;
        }
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


