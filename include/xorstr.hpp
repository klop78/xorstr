/*
 * Copyright 2017 - 2025 Justas Masiulis, klop
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JM_XORSTR_HPP
#define JM_XORSTR_HPP

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#include <arm_neon.h>
#elif defined(_M_X64) || defined(__amd64__) || defined(_M_IX86) || defined(__i386__)
#include <immintrin.h>
#else
#error Unsupported platform
#endif

#if defined(__clang__) || defined(__GNUC__)
    #define __cppversion __cplusplus
#elif defined(_MSC_VER)
    #define __cppversion _MSVC_LANG
#else
    #error Unsupported Compiler
#endif


#if __cppversion >= 201703L
    #define __cpp17OrGreater
#elif __cppversion >= 201402L
    #define __cpp14OrGreater
#else
    #error Unsupported c++11 or lower
#endif

#include <cstdint>
#include <cstddef>
#include <utility>
#include <type_traits>

#if defined(__cpp17OrGreater)
    #define xorstr(str) ::jm::xor_string([]() { return str; }, std::integral_constant<std::size_t, sizeof(str) / sizeof(*str)>{}, std::make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
#elif defined(__cpp14OrGreater)
    #define xorstr(str) ::jm::make_xorstring([]() { return str; }, std::make_index_sequence<sizeof(str) / sizeof(*str)>{}, std::make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})

#endif

#define xorstr_(str) xorstr(str).crypt_get()

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
#endif

namespace jm {

    namespace detail {

        template<std::size_t Size>
        XORSTR_FORCEINLINE constexpr std::size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<std::uint32_t Seed>
        XORSTR_FORCEINLINE constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for(char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<std::size_t S>
        XORSTR_FORCEINLINE constexpr std::uint64_t key8()
        {
            constexpr auto first_part  = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        // loads up to 8 characters of string into uint64 and xors it with the key
        template<std::size_t N, class CharT>
        XORSTR_FORCEINLINE constexpr std::uint64_t
        load_xored_str8(std::uint64_t key, std::size_t idx, const CharT* str) noexcept
        {
            using cast_type = typename std::make_unsigned<CharT>::type;
            constexpr auto value_size = sizeof(CharT);
            constexpr auto idx_offset = 8 / value_size;

            std::uint64_t value = key;
            for(std::size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i)
                value ^=
                    (std::uint64_t{ static_cast<cast_type>(str[i + idx * idx_offset]) }
                     << ((i % idx_offset) * 8 * value_size));

            return value;
        }

        // forces compiler to use registers instead of stuffing constants in rdata
        XORSTR_FORCEINLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm("" : "=r"(value) : "0"(value) :);
            return value;
#else
            volatile std::uint64_t reg = value;
            return reg;
#endif
        }

    } // namespace detail

#if defined(__cpp17OrGreater)
    template<class CharT, std::size_t Size, class Keys, class Indices>
    class xor_string;

    template<class CharT, std::size_t Size, std::uint64_t... Keys, std::size_t... Indices>
    class xor_string<CharT, Size, std::integer_sequence<std::uint64_t, Keys...>, std::index_sequence<Indices...>> {
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
        constexpr static inline std::uint64_t alignment = ((Size > 16) ? 32 : 16);    
#else
        constexpr static inline std::uint64_t alignment = 16;
#endif

        alignas(alignment) std::uint64_t _storage[sizeof...(Keys)];

    public:
        using value_type    = CharT;
        using size_type     = std::size_t;
        using pointer       = CharT*;
        using const_pointer = const CharT*;

        template<class L>
        XORSTR_FORCEINLINE xor_string(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) noexcept
            : _storage{ ::jm::detail::load_from_reg((std::integral_constant<std::uint64_t, detail::load_xored_str8<Size>(Keys, Indices, l())>::value))... }
        {}

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept
        {
            return Size - 1;
        }

        XORSTR_FORCEINLINE void crypt() noexcept
        {
            // everything is inlined by hand because a certain compiler with a certain linker is _very_ slow
#if defined(__clang__)
            alignas(alignment)
                std::uint64_t arr[]{ ::jm::detail::load_from_reg(Keys)... };
            std::uint64_t*    keys =
                (std::uint64_t*)::jm::detail::load_from_reg((std::uint64_t)arr);
#else
            alignas(alignment) std::uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : __builtin_neon_vst1q_v(
                                    reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                                    veorq_u64(__builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2, 51),
                                              __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(keys) + Indices * 2, 51)),
                                    51)), ...);
#else // GCC, MSVC
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : vst1q_u64(
                        reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                        veorq_u64(vld1q_u64(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2),
                                  vld1q_u64(reinterpret_cast<const uint64_t*>(keys) + Indices * 2)))), ...);
#endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
            ((Indices >= sizeof(_storage) / 32 ? static_cast<void>(0) : _mm256_store_si256(
                reinterpret_cast<__m256i*>(_storage) + Indices,
                _mm256_xor_si256(
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(_storage) + Indices),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(keys) + Indices)))), ...);

            if constexpr(sizeof(_storage) % 32 != 0)
                _mm_store_si128(
                    reinterpret_cast<__m128i*>(_storage + sizeof...(Keys) - 2),
                    _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage + sizeof...(Keys) - 2)),
                                  _mm_load_si128(reinterpret_cast<const __m128i*>(keys + sizeof...(Keys) - 2))));
#else
        ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : _mm_store_si128(
            reinterpret_cast<__m128i*>(_storage) + Indices,
            _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage) + Indices),
                          _mm_load_si128(reinterpret_cast<const __m128i*>(keys) + Indices)))), ...);
#endif
        }

        XORSTR_FORCEINLINE const_pointer get() const noexcept
        {
            return reinterpret_cast<const_pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer get() noexcept
        {
            return reinterpret_cast<pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer crypt_get() noexcept
        {
            // crypt() is inlined by hand because a certain compiler with a certain linker is _very_ slow
#if defined(__clang__)
            alignas(alignment)
                std::uint64_t arr[]{ ::jm::detail::load_from_reg(Keys)... };
            std::uint64_t*    keys =
                (std::uint64_t*)::jm::detail::load_from_reg((std::uint64_t)arr);
#else
            alignas(alignment) std::uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : __builtin_neon_vst1q_v(
                                    reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                                    veorq_u64(__builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2, 51),
                                              __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(keys) + Indices * 2, 51)),
                                    51)), ...);
#else // GCC, MSVC
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : vst1q_u64(
                        reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                        veorq_u64(vld1q_u64(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2),
                                  vld1q_u64(reinterpret_cast<const uint64_t*>(keys) + Indices * 2)))), ...);
#endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
            ((Indices >= sizeof(_storage) / 32 ? static_cast<void>(0) : _mm256_store_si256(
                reinterpret_cast<__m256i*>(_storage) + Indices,
                _mm256_xor_si256(
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(_storage) + Indices),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(keys) + Indices)))), ...);

            if constexpr(sizeof(_storage) % 32 != 0)
                _mm_store_si128(
                    reinterpret_cast<__m128i*>(_storage + sizeof...(Keys) - 2),
                    _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage + sizeof...(Keys) - 2)),
                                  _mm_load_si128(reinterpret_cast<const __m128i*>(keys + sizeof...(Keys) - 2))));
#else
        ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : _mm_store_si128(
            reinterpret_cast<__m128i*>(_storage) + Indices,
            _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage) + Indices),
                          _mm_load_si128(reinterpret_cast<const __m128i*>(keys) + Indices)))), ...);
#endif

            return (pointer)(_storage);
        }
    };

    template<class L, std::size_t Size, std::size_t... Indices>
    xor_string(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) -> xor_string<
                std::remove_const_t<std::remove_reference_t<decltype(l()[0])>>,
                Size,
                std::integer_sequence<std::uint64_t, detail::key8<Indices>()...>,
                std::index_sequence<Indices...>>;

#elif defined(__cpp14OrGreater)
    template<class _Ty, class _Seq, class _Keys, class _Indices>
    class xor_string;

    template<class _Ty, std::size_t... _Seq, std::uint64_t... _Keys, std::size_t... _Indices>
    class xor_string<_Ty, std::integer_sequence<std::size_t, _Seq...>, std::integer_sequence<std::uint64_t, _Keys...>, std::index_sequence<_Indices...>> {
    public:
        using value_type = _Ty;
        using size_type = std::size_t;
        using key_type = std::uint64_t;
        using pointer = _Ty*;
        using const_pointer = const _Ty*;
    private:

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)

        template<size_t I, size_t MaxBlocks>
        struct crypt_neon_block {
            static XORSTR_FORCEINLINE void execute(value_type* storage, key_type* keys) noexcept {
                static_assert(I < MaxBlocks, "Index out of bounds");
                vst1q_u64(
                    reinterpret_cast<uint64_t*>(storage) + I * 2,
                    veorq_u64(
                        __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(storage) + I * 2, 51),
                        __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(keys) + I * 2, 51)));
            }
        };

#else // GCC, MSVC
        template<size_t I, size_t MaxBlocks>
        struct crypt_neon_block {
            static XORSTR_FORCEINLINE void execute(value_type* storage, key_type* keys) noexcept {
                static_assert(I < MaxBlocks, "Index out of bounds");
                vst1q_u64(
                    reinterpret_cast<uint64_t*>(storage) + I * 2,
                    veorq_u64(
                        vld1q_u64(reinterpret_cast<const uint64_t*>(storage) + I * 2),
                        vld1q_u64(reinterpret_cast<const uint64_t*>(keys) + I * 2)));
            }
        };
#endif

        template<size_t I, size_t MaxBlocks>
        XORSTR_FORCEINLINE typename std::enable_if<(I < MaxBlocks), void>::type
            crypt_neon_single(key_type* keys) noexcept {
            crypt_neon_block<I, MaxBlocks>::execute(_storage, keys);
        }

        template<size_t I, size_t MaxBlocks>
        XORSTR_FORCEINLINE typename std::enable_if<(I >= MaxBlocks), void>::type
            crypt_neon_single(key_type* keys) noexcept {
            // Do nothing
        }

       
        template<size_t... Is>
        XORSTR_FORCEINLINE void crypt_neon_impl(key_type* keys, std::index_sequence<Is...>) noexcept {
            constexpr size_t max_blocks = sizeof(_storage) / 16;
            int dummy[] = { 0, (crypt_neon_single<Is, max_blocks>(keys), 0)... };
            (void)dummy; // suppress unused variable warning
        }

#else
        template<size_t I, size_t MaxBlocks>
        struct crypt_avx_block {
            static XORSTR_FORCEINLINE void execute(value_type* storage, key_type* keys) noexcept {
                static_assert(I < MaxBlocks, "Index out of bounds");
                _mm256_store_si256(
                    reinterpret_cast<__m256i*>(storage) + I,
                    _mm256_xor_si256(
                        _mm256_load_si256(reinterpret_cast<const __m256i*>(storage) + I),
                        _mm256_load_si256(reinterpret_cast<const __m256i*>(keys) + I)));
            }
        };

        template<size_t I, size_t MaxBlocks>
        struct crypt_sse_block {
            static XORSTR_FORCEINLINE void execute(value_type* storage, key_type* keys) noexcept {
                static_assert(I < MaxBlocks, "Index out of bounds");
                _mm_store_si128(
                    reinterpret_cast<__m128i*>(storage) + I,
                    _mm_xor_si128(
                        _mm_load_si128(reinterpret_cast<const __m128i*>(storage) + I),
                        _mm_load_si128(reinterpret_cast<const __m128i*>(keys) + I)));
            }
        };

        template<size_t I, size_t MaxBlocks>
        XORSTR_FORCEINLINE typename std::enable_if<(I < MaxBlocks), void>::type
            crypt_avx_single(key_type* keys) noexcept {
            crypt_avx_block<I, MaxBlocks>::execute(_storage, keys);
        }

        template<size_t I, size_t MaxBlocks>
        XORSTR_FORCEINLINE typename std::enable_if<(I >= MaxBlocks), void>::type
            crypt_avx_single(key_type* keys) noexcept {
            // Do nothing
        }

        template<size_t I, size_t MaxBlocks>
        XORSTR_FORCEINLINE typename std::enable_if<(I < MaxBlocks), void>::type
            crypt_sse_single(key_type* keys) noexcept {
            crypt_sse_block<I, MaxBlocks>::execute(_storage, keys);
        }

        template<size_t I, size_t MaxBlocks>
        XORSTR_FORCEINLINE typename std::enable_if<(I >= MaxBlocks), void>::type
            crypt_sse_single(key_type* keys) noexcept {
            // Do nothing
        }

        // Parameter pack expansion using dummy array trick
        template<size_t... Is>
        XORSTR_FORCEINLINE void crypt_avx_impl(key_type* keys, std::index_sequence<Is...>) noexcept {
            constexpr size_t max_blocks = sizeof(_storage) / 32;
            int dummy[] = { 0, (crypt_avx_single<Is, max_blocks>(keys), 0)... };
            (void)dummy; // suppress unused variable warning

            constexpr bool needs_sse_cleanup = (sizeof(_storage) % 32 != 0);
            crypt_sse_cleanup(keys, std::integral_constant<bool, needs_sse_cleanup>{});
        }

        template<size_t... Is>
        XORSTR_FORCEINLINE void crypt_sse_impl(key_type* keys, std::index_sequence<Is...>) noexcept {
            constexpr size_t max_blocks = sizeof(_storage) / 16;
            int dummy[] = { 0, (crypt_sse_single<Is, max_blocks>(keys), 0)... };
            (void)dummy; // suppress unused variable warning
        }

        // Helper for SSE cleanup - C++14 way using tag dispatch
        XORSTR_FORCEINLINE void crypt_sse_cleanup(key_type* keys, std::true_type) noexcept {
            constexpr auto aaa = sizeof...(_Keys);
            _mm_store_si128(
                reinterpret_cast<__m128i*>((key_type*)_storage + sizeof...(_Keys) - 2),
                _mm_xor_si128(
                    _mm_load_si128(reinterpret_cast<const __m128i*>((key_type*)_storage + sizeof...(_Keys) - 2)),
                    _mm_load_si128(reinterpret_cast<const __m128i*>(keys + sizeof...(_Keys) - 2))));
        }

        XORSTR_FORCEINLINE void crypt_sse_cleanup(key_type* keys, std::false_type) noexcept {
            // Do nothing when cleanup is not needed
        }
#endif
        

        value_type _storage[sizeof...(_Indices) * sizeof(key_type) / sizeof(value_type)];

    public:

        template<class L>
        XORSTR_FORCEINLINE constexpr xor_string(L l)
            : _storage{ load_xor_str1(l()[_Seq], _Seq)... }
        {}

        XORSTR_FORCEINLINE constexpr value_type load_xor_str1(value_type ch, std::size_t i) const
        { 
            key_type keys[]{ detail::load_from_reg(_Keys)... };

            using cast_type = typename std::make_unsigned<value_type>::type;
            constexpr auto value_size = sizeof(value_type);
            constexpr auto idx_offset = sizeof(key_type) / value_size;

            key_type value = keys[i / idx_offset];
            return ch ^ (cast_type)(value >> (i % idx_offset) * 8 * value_size);
        }

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept
        {
            return sizeof...(_Seq) - 1;
        }

        XORSTR_FORCEINLINE const_pointer get() const noexcept
        {
            return reinterpret_cast<const_pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer get() noexcept
        {
            return reinterpret_cast<pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer crypt_get() noexcept
        {
#if defined(__clang__)
            key_type arr[]{ detail::load_from_reg(_Keys)... };
            key_type* keys =
                (key_type*) detail::load_from_reg((key_type)arr);
#else
            key_type keys[]{ detail::load_from_reg(_Keys)... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            constexpr size_t max_blocks = sizeof(_storage) / 16;
            crypt_neon_impl(keys, std::make_index_sequence<max_blocks>{});
#else // GCC, MSVC
            constexpr size_t max_blocks = sizeof(_storage) / 16;
            crypt_neon_impl(keys, std::make_index_sequence<max_blocks>{});
#endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
            // AVX blocks (32 bytes each)
            constexpr size_t max_blocks = sizeof(_storage) / 32;
            crypt_avx_impl(keys, std::make_index_sequence<max_blocks>{});
#else
            // SSE blocks (16 bytes each)
            constexpr size_t max_blocks = sizeof(_storage) / 16;
            crypt_sse_impl(keys, std::make_index_sequence<max_blocks>{});
#endif

            return (pointer)(_storage);
        }
    };


    template <class L, std::size_t... _Seq, std::size_t... Indices>
    xor_string<
        std::remove_const_t<std::remove_reference_t<decltype(std::declval<L>()()[0])>>,
        std::index_sequence<_Seq...>,
        std::integer_sequence<std::uint64_t, detail::key8<Indices>()...>,
        std::index_sequence<Indices...>
    > constexpr make_xorstring(L l, std::index_sequence<_Seq...>, std::index_sequence<Indices...>) {

        return xor_string<
            std::remove_const_t<std::remove_reference_t<decltype(l()[0])>>,
            std::index_sequence<_Seq...>,
            std::integer_sequence<std::uint64_t, detail::key8<Indices>()...>,
            std::index_sequence<Indices...>
        >(l);
    }

#endif

} // namespace jm

#endif // include guard
