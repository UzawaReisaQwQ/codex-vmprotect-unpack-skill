#include "Activation.h"
#include "Encoding.h"
#include "XXTEA.h"
#include "VMProtectSDK.h"
#include <windows.h>
#include <bcrypt.h>
#include <wbemidl.h>
#include <array>
#include <memory>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace console_app2 {
	namespace {
		template<class T> struct ComRelease { void operator()(T* p) const { if (p) p->Release(); } };
		template<class T> using ComPtr = std::unique_ptr<T, ComRelease<T>>;
		struct Bstr {
			BSTR value;
			explicit Bstr(const wchar_t* text) : value(SysAllocString(text)) { if (!value) throw std::bad_alloc(); }
			~Bstr() { SysFreeString(value); }
			Bstr(const Bstr&) = delete;
			Bstr& operator=(const Bstr&) = delete;
		};
		struct ComScope {
			HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
			~ComScope() { if (SUCCEEDED(status)) CoUninitialize(); }
		};
		struct RegistryClose { void operator()(HKEY p) const { RegCloseKey(p); } };
		struct AlgorithmClose { void operator()(BCRYPT_ALG_HANDLE p) const { BCryptCloseAlgorithmProvider(p, 0); } };
		struct HashClose { void operator()(BCRYPT_HASH_HANDLE p) const { BCryptDestroyHash(p); } };

		bool IsWhitespace(wchar_t c) {
			return (c >= 0x09 && c <= 0x0D) || c == 0x20 || c == 0x85 || c == 0xA0
				|| c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028
				|| c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000;
		}

		std::string Sha256Hex(std::string_view text) {
			const auto bytes = Utf8Bytes(text);
			BCRYPT_ALG_HANDLE rawAlgorithm = nullptr;
			if (BCryptOpenAlgorithmProvider(&rawAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
				throw std::runtime_error("Cannot open SHA-256 provider");
			std::unique_ptr<void, AlgorithmClose> algorithm(rawAlgorithm);
			BCRYPT_HASH_HANDLE rawHash = nullptr;
			if (BCryptCreateHash(algorithm.get(), &rawHash, nullptr, 0, nullptr, 0, 0) < 0)
				throw std::runtime_error("Cannot create SHA-256 hash");
			std::unique_ptr<void, HashClose> hash(rawHash);
			// Chunking avoids truncating the Windows ULONG length parameter.
			std::size_t offset = 0;
			while (offset < bytes.size()) {
				const auto remaining = bytes.size() - offset;
				constexpr auto maxChunk = (std::numeric_limits<ULONG>::max)();
				const auto count = static_cast<ULONG>(remaining > maxChunk ? maxChunk : remaining);
				if (BCryptHashData(hash.get(), const_cast<PUCHAR>(bytes.data() + offset), count, 0) < 0)
					throw std::runtime_error("SHA-256 update failed");
				offset += count;
			}
			std::array<unsigned char, 32> digest{};
			if (BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
				throw std::runtime_error("SHA-256 finalization failed");
			constexpr char hex[] = "0123456789ABCDEF";
			std::string result;
			for (const auto value : digest) { result += hex[value >> 4]; result += hex[value & 15]; }
			return result;
		}
	}

	std::string MachineID::GetMachineGuid() {
		HKEY rawKey = nullptr;
		auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &rawKey);
		if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return {};
		if (status != ERROR_SUCCESS) throw std::runtime_error("Cannot open MachineGuid registry key");
		std::unique_ptr<std::remove_pointer_t<HKEY>, RegistryClose> key(rawKey);
		DWORD type = 0, size = 0;
		status = RegQueryValueExW(key.get(), L"MachineGuid", nullptr, &type, nullptr, &size);
		if (status == ERROR_FILE_NOT_FOUND) return {};
		if (status != ERROR_SUCCESS) throw std::runtime_error("Cannot query MachineGuid");
		std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');
		status = RegQueryValueExW(key.get(), L"MachineGuid", nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &size);
		if (status != ERROR_SUCCESS) throw std::runtime_error("Cannot read MachineGuid");
		if (type != REG_SZ && type != REG_EXPAND_SZ) throw std::runtime_error("MachineGuid must be a registry string");
		std::wstring value(buffer.data());
		if (type == REG_EXPAND_SZ) {
			const auto length = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
			if (!length) throw std::runtime_error("Cannot expand MachineGuid");
			std::vector<wchar_t> expanded(length);
			const auto written = ExpandEnvironmentStringsW(value.c_str(), expanded.data(), length);
			if (!written || written > length) throw std::runtime_error("Cannot expand MachineGuid");
			value.assign(expanded.data());
		}
		return ToUtf8(value);
	}

	std::string MachineID::GetCpuId() {
		try {
			ComScope com;
			if (FAILED(com.status) && com.status != RPC_E_CHANGED_MODE) return {};
			auto status = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
				RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
			if (FAILED(status) && status != RPC_E_TOO_LATE) return {};
			IWbemLocator* rawLocator = nullptr;
			status = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
				IID_IWbemLocator, reinterpret_cast<void**>(&rawLocator));
			ComPtr<IWbemLocator> locator(rawLocator);
			if (FAILED(status)) return {};
			IWbemServices* rawServices = nullptr;
			Bstr path(L"ROOT\\CIMV2");
			status = locator->ConnectServer(path.value, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &rawServices);
			ComPtr<IWbemServices> services(rawServices);
			if (FAILED(status)) return {};
			status = CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
				RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
			if (FAILED(status)) return {};
			Bstr language(L"WQL"), query(L"SELECT ProcessorId FROM Win32_Processor");
			IEnumWbemClassObject* rawEnumerator = nullptr;
			status = services->ExecQuery(language.value, query.value,
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &rawEnumerator);
			ComPtr<IEnumWbemClassObject> enumerator(rawEnumerator);
			if (FAILED(status)) return {};
			IWbemClassObject* rawObject = nullptr;
			ULONG count = 0;
			status = enumerator->Next(WBEM_INFINITE, 1, &rawObject, &count);
			ComPtr<IWbemClassObject> object(rawObject);
			if (FAILED(status) || count == 0) return {};
			struct Variant {
				VARIANT value;
				Variant() { VariantInit(&value); }
				~Variant() { VariantClear(&value); }
			} property;
			status = object->Get(L"ProcessorId", 0, &property.value, nullptr, nullptr);
			if (FAILED(status) || property.value.vt != VT_BSTR || !property.value.bstrVal) return {};
			std::wstring_view value(property.value.bstrVal, SysStringLen(property.value.bstrVal));
			while (!value.empty() && IsWhitespace(value.front())) value.remove_prefix(1);
			while (!value.empty() && IsWhitespace(value.back())) value.remove_suffix(1);
			return ToUtf8(value);
		}
		catch (...) { return {}; }
	}

	__declspec(noinline) std::string MachineID::GenerateActivateKey() {
		VMProtectBeginUltra("MachineID::GenerateActivateKey");
		const auto guid = GetMachineGuid();
		const auto cpu = GetCpuId();
		auto result = GenerateActivateKey(guid, cpu);
		VMProtectEnd();
		return result;
	}

	__declspec(noinline) std::string MachineID::GenerateActivateKey(std::string_view machineGuid, std::string_view cpuId) {
		VMProtectBeginUltra("MachineID::GenerateActivateKey.WithIdentifiers");
		const std::string raw = "MachineGuid=" + std::string(machineGuid)
			+ ";Salt1=114514;CPU=" + std::string(cpuId) + ";Salt2=C4D038B4BED09FDB1471EF51EC3A32CD";
		const Bytes encrypted{ 111,14,110,85,70,94,88,86,7,4,122,122,80,127,89,89,124,98,99,113,96,80,10,10 };
		const auto encoded = StringObfuscator::Decode(encrypted);
		const auto key = XOR::Decode(encoded);
		auto result = Xxtea::XXTEA::EncryptToBase64String(Sha256Hex(raw), key);
		VMProtectEnd();
		return result;
	}
}
