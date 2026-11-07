// Adapted from Ma Bingyao's XXTEA.cs, last modified March 10, 2015.
// XXTEA algorithm: David J. Wheeler and Roger M. Needham.
#include "XXTEA.h"
#include <array>
#include <stdexcept>
#include <limits>

namespace Xxtea {
using console_app2::Bytes;
namespace {
constexpr std::uint32_t delta = 0x9E3779B9u;
using Words = std::vector<std::uint32_t>;

Words ToWords(const Bytes& data, bool includeLength) {
    if (data.size() > (std::numeric_limits<std::uint32_t>::max)())
        throw std::length_error("XXTEA input exceeds the 32-bit length format");
    const auto count = (data.size() + 3) / 4;
    Words result(count + (includeLength ? 1 : 0), 0);
    if (includeLength) result[count] = static_cast<std::uint32_t>(data.size());
    for (std::size_t i = 0; i < data.size(); ++i)
        result[i / 4] |= static_cast<std::uint32_t>(data[i]) << ((i % 4) * 8);
    return result;
}

std::optional<Bytes> ToBytes(const Words& data, bool includeLength) {
    auto size = data.size() * 4;
    if (includeLength) {
        const auto length = static_cast<std::size_t>(data.back());
        size -= 4;
        if (length > size || size - length > 3) return std::nullopt;
        size = length;
    }
    Bytes result(size);
    for (std::size_t i = 0; i < size; ++i)
        result[i] = static_cast<std::uint8_t>(data[i / 4] >> ((i % 4) * 8));
    return result;
}

Words FixKey(const Bytes& key) {
    Bytes fixed(16, 0);
    for (std::size_t i = 0; i < key.size() && i < fixed.size(); ++i) fixed[i] = key[i];
    return ToWords(fixed, false);
}

std::uint32_t MX(std::uint32_t sum, std::uint32_t y, std::uint32_t z,
                 std::size_t p, std::uint32_t e, const Words& key) {
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
}

std::string DecodeResult(const std::optional<Bytes>& data) {
    if (!data) throw std::invalid_argument("Invalid XXTEA decrypted length");
    return console_app2::DecodeUtf8(*data);
}
}

Bytes XXTEA::Encrypt(const Bytes& data, const Bytes& key) {
    if (data.empty()) return data;
    auto words = ToWords(data, true);
    const auto fixedKey = FixKey(key);
    const auto n = words.size() - 1;
    std::uint32_t z = words[n], sum = 0;
    auto rounds = 6 + 52 / words.size();
    while (rounds-- > 0) {
        sum += delta;
        const auto e = (sum >> 2) & 3;
        for (std::size_t p = 0; p < n; ++p)
            z = (words[p] += MX(sum, words[p + 1], z, p, e, fixedKey));
        z = (words[n] += MX(sum, words[0], z, n, e, fixedKey));
    }
    return *ToBytes(words, false);
}

std::optional<Bytes> XXTEA::Decrypt(const Bytes& data, const Bytes& key) {
    if (data.empty()) return data;
    auto words = ToWords(data, false);
    const auto n = words.size() - 1;
    if (n >= 1) {
        const auto fixedKey = FixKey(key);
        std::uint32_t y = words[0];
        auto sum = static_cast<std::uint32_t>(6 + 52 / words.size()) * delta;
        while (sum != 0) {
            const auto e = (sum >> 2) & 3;
            for (auto p = n; p > 0; --p)
                y = (words[p] -= MX(sum, y, words[p - 1], p, e, fixedKey));
            y = (words[0] -= MX(sum, y, words[n], 0, e, fixedKey));
            sum -= delta;
        }
    }
    return ToBytes(words, true);
}

Bytes XXTEA::Encrypt(std::string_view data, std::string_view key) { return Encrypt(console_app2::Utf8Bytes(data), console_app2::Utf8Bytes(key)); }
Bytes XXTEA::Encrypt(std::string_view data, const Bytes& key) { return Encrypt(console_app2::Utf8Bytes(data), key); }
Bytes XXTEA::Encrypt(const Bytes& data, std::string_view key) { return Encrypt(data, console_app2::Utf8Bytes(key)); }
std::string XXTEA::EncryptToBase64String(const Bytes& data, const Bytes& key) { return console_app2::Base64Encode(Encrypt(data, key)); }
std::string XXTEA::EncryptToBase64String(std::string_view data, std::string_view key) { return console_app2::Base64Encode(Encrypt(data, key)); }
std::string XXTEA::EncryptToBase64String(std::string_view data, const Bytes& key) { return console_app2::Base64Encode(Encrypt(data, key)); }
std::string XXTEA::EncryptToBase64String(const Bytes& data, std::string_view key) { return console_app2::Base64Encode(Encrypt(data, key)); }
std::optional<Bytes> XXTEA::Decrypt(const Bytes& data, std::string_view key) { return Decrypt(data, console_app2::Utf8Bytes(key)); }
std::optional<Bytes> XXTEA::DecryptBase64String(std::string_view data, const Bytes& key) { return Decrypt(console_app2::Base64Decode(data), key); }
std::optional<Bytes> XXTEA::DecryptBase64String(std::string_view data, std::string_view key) { return Decrypt(console_app2::Base64Decode(data), key); }
std::string XXTEA::DecryptToString(const Bytes& data, const Bytes& key) { return DecodeResult(Decrypt(data, key)); }
std::string XXTEA::DecryptToString(const Bytes& data, std::string_view key) { return DecodeResult(Decrypt(data, key)); }
std::string XXTEA::DecryptBase64StringToString(std::string_view data, const Bytes& key) { return DecodeResult(DecryptBase64String(data, key)); }
std::string XXTEA::DecryptBase64StringToString(std::string_view data, std::string_view key) { return DecodeResult(DecryptBase64String(data, key)); }
}
