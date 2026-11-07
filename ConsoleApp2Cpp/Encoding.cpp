#include "Encoding.h"
#include <windows.h>
#include <array>
#include <limits>
#include <stdexcept>

namespace console_app2 {
	namespace {
		int CheckedLength(std::size_t size) {
			if (size > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
				throw std::length_error("Text exceeds Windows conversion limit");
			return static_cast<int>(size);
		}
		constexpr std::array<std::uint8_t, 8> xorKey{ 0x37, 0xA1, 0x52, 0xC8, 0x19, 0x73, 0xE4, 0x2B };
		constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	}

	std::wstring FromUtf8(std::string_view text) {
		std::wstring result;
		for (std::size_t i = 0; i < text.size();) {
			const auto first = static_cast<std::uint8_t>(text[i++]);
			if (first < 0x80) { result += static_cast<wchar_t>(first); continue; }
			unsigned length = 0;
			std::uint32_t codepoint = 0;
			if (first >= 0xC2 && first <= 0xDF) { length = 2; codepoint = first & 0x1F; }
			else if (first >= 0xE0 && first <= 0xEF) { length = 3; codepoint = first & 0x0F; }
			else if (first >= 0xF0 && first <= 0xF4) { length = 4; codepoint = first & 0x07; }
			else { result += L'\uFFFD'; continue; }
			bool valid = true;
			for (unsigned j = 1; j < length; ++j) {
				if (i == text.size()) { valid = false; break; }
				const auto next = static_cast<std::uint8_t>(text[i]);
				if (next < 0x80 || next > 0xBF
					|| (j == 1 && ((first == 0xE0 && next < 0xA0)
						|| (first == 0xED && next > 0x9F)
						|| (first == 0xF0 && next < 0x90)
						|| (first == 0xF4 && next > 0x8F)))) {
					valid = false;
					break;
				}
				++i;
				codepoint = (codepoint << 6) | (next & 0x3F);
			}
			if (!valid) result += L'\uFFFD';
			else if (codepoint <= 0xFFFF) result += static_cast<wchar_t>(codepoint);
			else {
				codepoint -= 0x10000;
				result += static_cast<wchar_t>(0xD800 + (codepoint >> 10));
				result += static_cast<wchar_t>(0xDC00 + (codepoint & 0x3FF));
			}
		}
		return result;
	}

	std::string ToUtf8(std::wstring_view text) {
		if (text.empty()) return {};
		const int length = CheckedLength(text.size());
		const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), length, nullptr, 0, nullptr, nullptr);
		if (!size) throw std::runtime_error("UTF-8 encoding failed");
		std::string result(size, '\0');
		if (!WideCharToMultiByte(CP_UTF8, 0, text.data(), length, result.data(), size, nullptr, nullptr))
			throw std::runtime_error("UTF-8 encoding failed");
		return result;
	}

	std::string DecodeUtf8(const Bytes& bytes) {
		if (bytes.empty()) return {};
		return ToUtf8(FromUtf8(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size())));
	}

	Bytes Utf8Bytes(std::string_view text) {
		const auto normalized = ToUtf8(FromUtf8(text));
		return Bytes(normalized.begin(), normalized.end());
	}

	std::string Base64Encode(const Bytes& data) {
		std::string result;
		result.reserve((data.size() + 2) / 3 * 4);
		for (std::size_t i = 0; i < data.size(); i += 3) {
			const auto value = (static_cast<std::uint32_t>(data[i]) << 16)
				| (i + 1 < data.size() ? static_cast<std::uint32_t>(data[i + 1]) << 8 : 0)
				| (i + 2 < data.size() ? data[i + 2] : 0);
			result += alphabet[(value >> 18) & 63];
			result += alphabet[(value >> 12) & 63];
			result += i + 1 < data.size() ? alphabet[(value >> 6) & 63] : '=';
			result += i + 2 < data.size() ? alphabet[value & 63] : '=';
		}
		return result;
	}

	Bytes Base64Decode(std::string_view text) {
		std::string clean;
		for (char c : text) {
			if (c != ' ' && c != '\t' && c != '\r' && c != '\n') clean += c;
		}
		if (clean.size() % 4) throw std::invalid_argument("Invalid Base64 length");
		Bytes result;
		for (std::size_t i = 0; i < clean.size(); i += 4) {
			std::uint32_t value = 0;
			unsigned padding = 0;
			for (unsigned j = 0; j < 4; ++j) {
				const char c = clean[i + j];
				value <<= 6;
				if (c == '=') {
					if (j < 2 || i + 4 != clean.size()) throw std::invalid_argument("Invalid Base64 padding");
					++padding;
				}
				else {
					const auto position = std::string_view(alphabet, 64).find(c);
					if (padding || position == std::string_view::npos) throw std::invalid_argument("Invalid Base64 character");
					value |= static_cast<std::uint32_t>(position);
				}
			}
			result.push_back(static_cast<std::uint8_t>(value >> 16));
			if (padding < 2) result.push_back(static_cast<std::uint8_t>(value >> 8));
			if (padding < 1) result.push_back(static_cast<std::uint8_t>(value));
		}
		return result;
	}

	std::string XOR::Encode(std::string_view input) {
		auto data = Utf8Bytes(input);
		for (std::size_t i = 0; i < data.size(); ++i) data[i] ^= xorKey[i % xorKey.size()];
		return Base64Encode(data);
	}

	std::string XOR::Decode(std::string_view input) {
		auto data = Base64Decode(input);
		for (std::size_t i = 0; i < data.size(); ++i) data[i] ^= xorKey[i % xorKey.size()];
		return DecodeUtf8(data);
	}

	std::string StringObfuscator::Decode(const Bytes& encoded) {
		auto data = encoded;
		for (auto& value : data) value ^= 0x37;
		return DecodeUtf8(data);
	}
}
