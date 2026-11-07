#include "Activation.h"
#include "VMProtectSDK.h"
#include <iostream>
#include <string>

int main() {
	VMProtectBeginUltra("main");
	int exitCode = 0;
	try {
		std::cout << "Enter your key: " << std::endl;
		const auto activateKey = console_app2::MachineID::GenerateActivateKey();
		//std::cout << activateKey << std::endl;
		std::string userInput;
		const bool receivedInput = static_cast<bool>(std::getline(std::cin, userInput));
		if (!userInput.empty() && userInput.back() == '\r') userInput.pop_back();
		std::cout << (receivedInput && userInput == activateKey
			? "Product Activated" : "Wrong ActivateKey :(") << std::endl;
		std::getline(std::cin, userInput);
	}
	catch (const std::exception& error) {
		std::cerr << error.what() << std::endl;
		exitCode = 1;
	}
	VMProtectEnd();
	return exitCode;
}
