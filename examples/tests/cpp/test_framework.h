// A tiny self-registering test framework (no external dependency).
#pragma once

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace apgtest {

struct TestCase {
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& registry();
int& failure_count();
void report_failure(const char* file, int line, const std::string& what);

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back(TestCase{name, fn}); }
};

}  // namespace apgtest

#define APG_TEST(name)                                         \
    static void name();                                        \
    static ::apgtest::Registrar registrar_##name(#name, &name); \
    static void name()

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) ::apgtest::report_failure(__FILE__, __LINE__, #cond);   \
    } while (0)

#define CHECK_EQ(a, b)                                                                                      \
    do {                                                                                                    \
        const auto va__ = (a);                                                                              \
        const auto vb__ = (b);                                                                              \
        if (!(va__ == vb__)) {                                                                              \
            ::apgtest::report_failure(__FILE__, __LINE__, std::string(#a " == " #b " failed: ") +           \
                                                             ::apgtest::show(va__) + " vs " + ::apgtest::show(vb__)); \
        }                                                                                                   \
    } while (0)

#define CHECK_NEAR(a, b, eps)                                                                                \
    do {                                                                                                     \
        const double va__ = (a);                                                                             \
        const double vb__ = (b);                                                                             \
        if (!(std::fabs(va__ - vb__) <= (eps))) {                                                            \
            ::apgtest::report_failure(__FILE__, __LINE__, std::string(#a " ~= " #b " failed: ") +            \
                                                             std::to_string(va__) + " vs " + std::to_string(vb__)); \
        }                                                                                                    \
    } while (0)

namespace apgtest {
inline std::string show(const std::string& s) { return "\"" + s + "\""; }
inline std::string show(const char* s) { return std::string("\"") + s + "\""; }
inline std::string show(bool b) { return b ? "true" : "false"; }
template <class T>
inline std::string show(const T& v) {
    return std::to_string(v);
}
}  // namespace apgtest
