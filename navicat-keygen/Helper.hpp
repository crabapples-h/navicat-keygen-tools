#include <iostream>
#include <string>
#include <vector>

namespace Helper {
    template<int min_num, int max_num>
    bool ReadNumber(int& num, const char* msg, const char* err_msg) {
        int temp;
        std::string input;
        while (true) {
            std::cout << msg;
            if (!std::getline(std::cin, input))
                return false;

            try {
                temp = std::stoi(input, nullptr, 0);
                if (min_num <= temp && temp <= max_num) {
                    num = temp;
                    return true;
                } else {
                    throw std::invalid_argument("Invalid number");
                }
            } catch (...) {
                std::cout << err_msg << std::endl;
            }
        }
    }

    template<typename _Type>
    struct ResourceGuard {
        _Type* ptr;

        explicit ResourceGuard(_Type* p) noexcept : ptr(p) {}

        ~ResourceGuard() {
            if (ptr) {
                delete ptr;
                ptr = nullptr;
            }
        }
    };

    std::string base64_encode(const std::vector<uint8_t>& bindata);
    std::vector<uint8_t> base64_decode(const std::string& ascdata);
}
