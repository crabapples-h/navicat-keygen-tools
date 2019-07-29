#pragma once
#include <type_traits>
#include <utility>

template<typename __ResourceTraits, typename __LambdaReleasor = void>
class ResourceOwned {
private:

    using __HandleType = typename __ResourceTraits::HandleType;
    static_assert(std::is_pod_v<__HandleType>);

    __HandleType        pvt_Handle;
    __LambdaReleasor    pvt_Releasor;

public:

    //
    // Construct from custom releasor.
    // ``pvt_Handle` will be set to an invalid value.
    //
    ResourceOwned(__ResourceTraits, __LambdaReleasor&& Releasor) noexcept :
        pvt_Handle(__ResourceTraits::InvalidValue),
        pvt_Releasor(std::forward<__LambdaReleasor>(Releasor)) {}

    //
    // Construct from handle given and custom releasor.
    //
    ResourceOwned(__ResourceTraits, const __HandleType& Handle, __LambdaReleasor&& Releasor) noexcept :
        pvt_Handle(Handle),
        pvt_Releasor(std::forward<__LambdaReleasor>(Releasor)) {}

    //
    // ResourceOwned doesn't allow to copy.
    // Because it takes `pvt_Handle` exclusively.
    //
    ResourceOwned(const ResourceOwned<__ResourceTraits, __LambdaReleasor>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned(ResourceOwned<__ResourceTraits, __LambdaReleasor>&& Other) noexcept :
        pvt_Handle(Other.pvt_Handle),
        pvt_Releasor(std::move(Other.pvt_Releasor))
    {
        Other.pvt_Handle = __ResourceTraits::InvalidValue;
    }

    //
    // ResourceOwned doesn't allow to copy.
    // Because it takes `pvt_Handle` exclusively.
    //
    ResourceOwned<__ResourceTraits, __LambdaReleasor>&
    operator=(const ResourceOwned<__ResourceTraits, __LambdaReleasor>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned<__ResourceTraits, __LambdaReleasor>&
    operator=(ResourceOwned<__ResourceTraits, __LambdaReleasor>&& Other) noexcept {
        this->pvt_Handle = Other.pvt_Handle;
        this->pvt_Releasor = std::move(Other.pvt_Releasor);
        Other.pvt_Handle = __ResourceTraits::InvalidValue;
        return *this;
    }

    [[nodiscard]]
    operator const __HandleType&() const noexcept { // NOLINT: Allow implicit conversion.
        return this->pvt_Handle;
    }

    template<typename __AsType, bool __IsPointer = std::is_pointer_v<__HandleType>, typename = std::enable_if_t<__IsPointer>>
    [[nodiscard]]
    __AsType As() const noexcept {
        return reinterpret_cast<__AsType>(this->pvt_Handle);
    }

    template<bool __IsPointer = std::is_pointer_v<__HandleType>, typename = typename std::enable_if_t<__IsPointer>>
    [[nodiscard]]
    __HandleType operator->() const noexcept {
        return this->pvt_Handle;
    }

    [[nodiscard]]
    bool IsValid() const noexcept {
        return __ResourceTraits::IsValid(this->pvt_Handle);
    }

    [[nodiscard]]
    const __HandleType& Get() const noexcept {
        return this->pvt_Handle;
    }

    template<typename __ReturnType = __HandleType*>
    [[nodiscard]]
    __ReturnType GetAddress() noexcept {
        return reinterpret_cast<__ReturnType>(&this->pvt_Handle);
    }

    void TakeOver(const __HandleType& Handle) {
        if (__ResourceTraits::IsValid(this->pvt_Handle) == true) {
            this->pvt_Releasor(this->pvt_Handle);
        }
        this->pvt_Handle = Handle;
    }

    void Discard() noexcept {
        this->pvt_Handle = __ResourceTraits::InvalidValue;
    }

    [[nodiscard]]
    __HandleType Transfer() noexcept {
        __HandleType t = this->pvt_Handle;
        this->pvt_Handle = __ResourceTraits::InvalidValue;
        return t;
    }

    void Release() {
        if (__ResourceTraits::IsValid(this->pvt_Handle)) {
            this->pvt_Releasor(this->pvt_Handle);
            this->pvt_Handle = __ResourceTraits::InvalidValue;
        }
    }

    ~ResourceOwned() {
        if (__ResourceTraits::IsValid(this->pvt_Handle)) {
            this->pvt_Releasor(this->pvt_Handle);
            this->pvt_Handle = __ResourceTraits::InvalidValue;
        }
    }
};

template<typename __ResourceTraits>
class ResourceOwned<__ResourceTraits, void> {
private:

    using __HandleType = typename __ResourceTraits::HandleType;
    static_assert(std::is_pod_v<__HandleType>);

    __HandleType        pvt_Handle;

public:

    //
    // Construct from custom releasor.
    // ``pvt_Handle` will be set to an invalid value.
    //
    explicit
    ResourceOwned(__ResourceTraits) noexcept :
        pvt_Handle(__ResourceTraits::InvalidValue) {}

    //
    // Construct from handle given and custom releasor.
    //
    ResourceOwned(__ResourceTraits, const __HandleType& Handle) noexcept :
        pvt_Handle(Handle) {}

    //
    // ResourceOwned doesn't allow to copy.
    // Because it takes `pvt_Handle` exclusively.
    //
    ResourceOwned(const ResourceOwned<__ResourceTraits, void>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned(ResourceOwned<__ResourceTraits, void>&& Other) noexcept :
        pvt_Handle(Other.pvt_Handle)
    {
        Other.pvt_Handle = __ResourceTraits::InvalidValue;
    }

    //
    // ResourceOwned doesn't allow to copy.
    // Because it takes `pvt_Handle` exclusively.
    //
    ResourceOwned<__ResourceTraits, void>&
    operator=(const ResourceOwned<__ResourceTraits, void>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned<__ResourceTraits, void>&
    operator=(ResourceOwned<__ResourceTraits, void>&& Other) noexcept {
        this->pvt_Handle = Other.pvt_Handle;
        Other.pvt_Handle = __ResourceTraits::InvalidValue;
        return *this;
    }

    [[nodiscard]]
    operator const __HandleType&() const noexcept { // NOLINT: Allow implicit conversion.
        return this->pvt_Handle;
    }

    template<typename __AsType, bool __IsPointer = std::is_pointer_v<__HandleType>, typename = typename std::enable_if_t<__IsPointer>>
    [[nodiscard]]
    __AsType As() const noexcept {
        return reinterpret_cast<__AsType>(this->pvt_Handle);
    }

    template<bool __IsPointer = std::is_pointer_v<__HandleType>, typename = typename std::enable_if_t<__IsPointer>>
    [[nodiscard]]
    __HandleType operator->() const noexcept {
        return this->pvt_Handle;
    }

    [[nodiscard]]
    bool IsValid() const noexcept {
        return __ResourceTraits::IsValid(this->pvt_Handle);
    }

    [[nodiscard]]
    const __HandleType& Get() const noexcept {
        return this->pvt_Handle;
    }

    template<typename __ReturnType = __HandleType*>
    [[nodiscard]]
    __ReturnType GetAddress() noexcept {
        return reinterpret_cast<__ReturnType>(&this->pvt_Handle);
    }

    void TakeOver(const __HandleType& Handle) {
        if (__ResourceTraits::IsValid(this->pvt_Handle) == true) {
            __ResourceTraits::Releasor(this->pvt_Handle);
        }
        this->pvt_Handle = Handle;
    }

    void Discard() noexcept {
        this->pvt_Handle = __ResourceTraits::InvalidValue;
    }

    [[nodiscard]]
    __HandleType Transfer() noexcept {
        __HandleType t = this->pvt_Handle;
        this->pvt_Handle = __ResourceTraits::InvalidValue;
        return t;
    }

    void Release() {
        if (__ResourceTraits::IsValid(this->pvt_Handle)) {
            __ResourceTraits::Releasor(this->pvt_Handle);
            this->pvt_Handle = __ResourceTraits::InvalidValue;
        }
    }

    ~ResourceOwned() {
        if (__ResourceTraits::IsValid(this->pvt_Handle)) {
            __ResourceTraits::Releasor(this->pvt_Handle);
            this->pvt_Handle = __ResourceTraits::InvalidValue;
        }
    }
};

template<typename __ResourceTraits>
ResourceOwned(__ResourceTraits) ->
    ResourceOwned<__ResourceTraits, void>;

template<typename __ResourceTraits, typename __ArgType>
ResourceOwned(__ResourceTraits, __ArgType&&) ->
    ResourceOwned<
        __ResourceTraits,
        std::conditional_t<
            std::is_same_v<std::remove_cv_t<std::remove_reference_t<__ArgType>>, typename __ResourceTraits::HandleType> == false,
            std::remove_reference_t<__ArgType>,
            void
        >
    >;

template<typename __ResourceTraits, typename __LambdaReleasor>
ResourceOwned(__ResourceTraits, const typename __ResourceTraits::HandleType&, __LambdaReleasor&&) ->
    ResourceOwned<__ResourceTraits, std::remove_reference_t<__LambdaReleasor>>;

template<typename __ClassType>
struct CppObjectTraits {
    using HandleType = __ClassType*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) {
        delete Handle;
    }
};

template<typename __ClassType>
struct CppDynamicArrayTraits {
    using HandleType = __ClassType*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) {
        delete[] Handle;
    }
};
