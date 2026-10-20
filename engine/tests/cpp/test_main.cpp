#include <cstring>
#include <exception>

#include "test_framework.h"

namespace apgtest {

std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

int& failure_count() {
    static int n = 0;
    return n;
}

void report_failure(const char* file, int line, const std::string& what) {
    ++failure_count();
    std::fprintf(stderr, "    FAILED %s:%d: %s\n", file, line, what.c_str());
}

}  // namespace apgtest

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int ran = 0, failed_tests = 0;
    for (const apgtest::TestCase& t : apgtest::registry()) {
        if (filter != nullptr && std::strstr(t.name, filter) == nullptr) continue;
        const int before = apgtest::failure_count();
        std::fprintf(stderr, "[ RUN  ] %s\n", t.name);
        try {
            t.fn();
        } catch (const std::exception& e) {
            apgtest::report_failure(__FILE__, __LINE__, std::string("uncaught exception: ") + e.what());
        } catch (...) {
            apgtest::report_failure(__FILE__, __LINE__, "uncaught non-standard exception");
        }
        ++ran;
        if (apgtest::failure_count() != before) {
            ++failed_tests;
            std::fprintf(stderr, "[ FAIL ] %s\n", t.name);
        } else {
            std::fprintf(stderr, "[  OK  ] %s\n", t.name);
        }
    }
    std::fprintf(stderr, "\n%d test(s) run, %d failed\n", ran, failed_tests);
    return failed_tests == 0 ? 0 : 1;
}
