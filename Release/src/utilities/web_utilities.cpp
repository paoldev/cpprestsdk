/***
 * Copyright (C) Microsoft. All rights reserved.
 * Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.
 *
 * =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *
 * Credential and proxy utilities.
 *
 * For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 ****/

#include "stdafx.h"

#include <assert.h>

#if defined(_WIN32) && !defined(__cplusplus_winrt)
#include <Wincrypt.h>
#endif

#if defined(__cplusplus_winrt)
#include <robuffer.h>
#endif

namespace web
{
namespace details
{
#ifdef _WIN32
#if _WIN32_WINNT >= _WIN32_WINNT_VISTA

struct UtfConverter
{
    template<typename T>
    static plaintext_string<T>&& convert(plaintext_string<T>&& s)
    {
        return std::move(s);
    }

    template<typename T>
    static plaintext_string<utf8string> convert(const plaintext_string<utf16string>& s)
    {
        // The destructor of s will securely cleanup this memory area.
        // Can't use to_utf8string or utf16_to_utf8, to avoid unneeded string copies (unless additional implementation
        // will be exposed).
        int numChars = ((*s).size() > 0)
                           ? WideCharToMultiByte(
                                 CP_UTF8, 0, (*s).data(), static_cast<int>((*s).size()), nullptr, 0, nullptr, nullptr)
                           : 0;
        auto result = plaintext_string<utf8string>(new utf8string(numChars, L'0'));
        if (numChars > 0)
        {
            WideCharToMultiByte(
                CP_UTF8, 0, (*s).data(), static_cast<int>((*s).size()), &(*result)[0], numChars, nullptr, nullptr);
        }

        return result;
    }

    template<typename T>
    static plaintext_string<utf16string> convert(const plaintext_string<utf8string>& s)
    {
        // The destructor of s will securely cleanup this memory area.
        // Can't use to_utf16string or utf8_to_utf16, to avoid unneeded string copies (unless additional implementation
        // will be exposed).
        int numWChars = ((*s).size() > 0)
                            ? MultiByteToWideChar(CP_UTF8, 0, (*s).data(), static_cast<int>((*s).size()), nullptr, 0)
                            : 0;
        auto result = plaintext_string<utf16string>(new utf16string(numWChars, L'0'));
        if (numWChars > 0)
        {
            MultiByteToWideChar(CP_UTF8, 0, (*s).data(), static_cast<int>((*s).size()), &(*result)[0], numWChars);
        }

        return result;
    }
};

#ifdef __cplusplus_winrt

// Helper function to zero out memory of an IBuffer.
void winrt_secure_zero_buffer(Windows::Storage::Streams::IBuffer ^ buffer)
{
    Microsoft::WRL::ComPtr<IInspectable> bufferInspectable(reinterpret_cast<IInspectable*>(buffer));
    Microsoft::WRL::ComPtr<Windows::Storage::Streams::IBufferByteAccess> bufferByteAccess;
    bufferInspectable.As(&bufferByteAccess);

    // This shouldn't happen but if can't get access to the raw bytes for some reason
    // then we can't zero out.
    byte* rawBytes;
    if (bufferByteAccess->Buffer(&rawBytes) == S_OK)
    {
        SecureZeroMemory(rawBytes, buffer->Length);
    }
}

winrt_encryption::winrt_encryption(const ::utility::string_t& data)
{
    auto provider = ref new Windows::Security::Cryptography::DataProtection::DataProtectionProvider(
        ref new Platform::String(L"Local=user"));

    // Create buffer containing plain text password.
    Platform::ArrayReference<unsigned char> arrayref(
        reinterpret_cast<unsigned char*>(const_cast<::utility::string_t::value_type*>(data.c_str())),
        static_cast<unsigned int>(data.size()) * sizeof(::utility::string_t::value_type));
    Windows::Storage::Streams::IBuffer ^ plaintext =
        Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(arrayref);
    m_buffer = pplx::create_task(provider->ProtectAsync(plaintext));
    m_buffer.then(
        [plaintext](pplx::task<Windows::Storage::Streams::IBuffer ^>) { winrt_secure_zero_buffer(plaintext); });
}

plaintext_string<::utility::string_t> winrt_encryption::decrypt_t() const
{
    // To fully guarantee asynchrony would require significant impact on existing code. This code path
    // is never run on a user's thread and is only done once when setting up a connection.
    auto encrypted = m_buffer.get();
    auto provider = ref new Windows::Security::Cryptography::DataProtection::DataProtectionProvider();
    auto plaintext = pplx::create_task(provider->UnprotectAsync(encrypted)).get();

    // Get access to raw bytes in plain text buffer.
    Microsoft::WRL::ComPtr<IInspectable> bufferInspectable(reinterpret_cast<IInspectable*>(plaintext));
    Microsoft::WRL::ComPtr<Windows::Storage::Streams::IBufferByteAccess> bufferByteAccess;
    bufferInspectable.As(&bufferByteAccess);
    byte* rawPlaintext;
    const auto& result = bufferByteAccess->Buffer(&rawPlaintext);
    if (result != S_OK)
    {
        throw ::utility::details::create_system_error(result);
    }

    // Construct string and zero out memory from plain text buffer.
    auto data = plaintext_string<::utility::string_t>(new ::utility::string_t(reinterpret_cast<const ::utility::string_t::value_type*>(rawPlaintext),
                                plaintext->Length / sizeof(::utility::string_t::value_type)));
    SecureZeroMemory(rawPlaintext, plaintext->Length);
    return std::move(data);
}

template<typename T>
plaintext_string<T> winrt_encryption::decrypt() const
{
    return std::move(UtfConverter::convert<T>(decrypt_t()));
}

#else  // ^^^ __cplusplus_winrt ^^^ // vvv !__cplusplus_winrt vvv

win32_encryption::win32_encryption(const ::utility::string_t& data) : m_numCharacters(data.size())
{
    // Early return because CryptProtectMemory crashes with empty string
    if (m_numCharacters == 0)
    {
        return;
    }

    if (data.size() > (std::numeric_limits<DWORD>::max)() / sizeof(::utility::string_t::value_type))
    {
        throw std::length_error("Encryption string too long");
    }

    // See MultiByteToWideChar and WideCharToMultiByte called in UtfConverter.
    if (data.size() > (std::numeric_limits<int>::max)() / sizeof(::utility::string_t::value_type))
    {
        throw std::length_error("Encryption string too long");
    }

    const auto dataSizeDword = static_cast<DWORD>(data.size() * sizeof(::utility::string_t::value_type));

    // Round up dataSizeDword to be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE
    static_assert(CRYPTPROTECTMEMORY_BLOCK_SIZE == 16, "Power of 2 assumptions in this bit masking violated");
    const auto mask = static_cast<DWORD>(CRYPTPROTECTMEMORY_BLOCK_SIZE - 1u);
    const auto dataNumBytes = (dataSizeDword & ~mask) + ((dataSizeDword & mask) != 0) * CRYPTPROTECTMEMORY_BLOCK_SIZE;
    assert((dataNumBytes % CRYPTPROTECTMEMORY_BLOCK_SIZE) == 0);
    assert(dataNumBytes >= dataSizeDword);
    m_buffer.resize(dataNumBytes);
    memcpy_s(m_buffer.data(), m_buffer.size(), data.c_str(), dataNumBytes);
    if (!CryptProtectMemory(m_buffer.data(), dataNumBytes, CRYPTPROTECTMEMORY_SAME_PROCESS))
    {
        throw ::utility::details::create_system_error(GetLastError());
    }
}

win32_encryption::~win32_encryption() { SecureZeroMemory(m_buffer.data(), m_buffer.size()); }

plaintext_string<::utility::string_t> win32_encryption::decrypt_t() const
{
    // Copy the buffer and decrypt to avoid having to re-encrypt.
    auto result = plaintext_string<::utility::string_t>(
        new ::utility::string_t(reinterpret_cast<const ::utility::string_t::value_type*>(m_buffer.data()),
                                m_buffer.size() / sizeof(::utility::string_t::value_type)));
    auto& data = *result;
    if (!m_buffer.empty())
    {
        if (!CryptUnprotectMemory(&data[0], static_cast<DWORD>(m_buffer.size()), CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            throw ::utility::details::create_system_error(GetLastError());
        }

        assert(m_numCharacters <= m_buffer.size());
        SecureZeroMemory(&data[m_numCharacters], data.size() - m_numCharacters);
        data.erase(m_numCharacters);
    }

    return result;
}

template<typename T>
plaintext_string<T> win32_encryption::decrypt() const
{
    return std::move(UtfConverter::convert<T>(decrypt_t()));
}

#endif // __cplusplus_winrt
#endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA
#endif // _WIN32

template<typename T>
void zero_memory_deleter<T>::operator()(T* data) const
{
    (void)data;
#ifdef _WIN32
    SecureZeroMemory(&(*data)[0], data->size() * sizeof(typename T::value_type));
    delete data;
#endif
}
} // namespace details

} // namespace web
