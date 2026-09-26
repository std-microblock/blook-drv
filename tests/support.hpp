#pragma once

#include <cstdlib>
#include <iostream>
#include <source_location>
#include <string_view>

namespace test {
inline unsigned checks{};
inline void check(
    bool condition, std::string_view message,
    std::source_location location = std::source_location::current()) {
    ++checks;
    if (!condition) {
        std::cerr << location.file_name() << ":" << location.line()
                  << ": FAIL: " << message << "\n";
        std::exit(EXIT_FAILURE);
    }
}
inline int finish() {
    std::cout << "PASS: " << checks << " checks\n";
    return EXIT_SUCCESS;
}
}  // namespace test
