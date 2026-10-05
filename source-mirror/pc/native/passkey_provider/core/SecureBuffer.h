#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace fae::vault::passkeys
{
    class SecureBuffer final
    {
    public:
        SecureBuffer() = default;
        explicit SecureBuffer(std::vector<std::uint8_t> value) : m_value(std::move(value)) {}
        SecureBuffer(SecureBuffer const&) = delete;
        SecureBuffer& operator=(SecureBuffer const&) = delete;
        SecureBuffer(SecureBuffer&& other) noexcept : m_value(std::move(other.m_value)) { other.clear(); }
        SecureBuffer& operator=(SecureBuffer&& other) noexcept
        {
            if (this != &other)
            {
                clear();
                m_value = std::move(other.m_value);
                other.clear();
            }
            return *this;
        }
        ~SecureBuffer() { clear(); }

        std::uint8_t* data() noexcept { return m_value.data(); }
        std::uint8_t const* data() const noexcept { return m_value.data(); }
        std::size_t size() const noexcept { return m_value.size(); }
        bool empty() const noexcept { return m_value.empty(); }
        std::vector<std::uint8_t> const& view() const noexcept { return m_value; }

        void clear() noexcept
        {
            if (!m_value.empty())
            {
                SecureZeroMemory(m_value.data(), m_value.size());
                m_value.clear();
                m_value.shrink_to_fit();
            }
        }

    private:
        std::vector<std::uint8_t> m_value;
    };
}
