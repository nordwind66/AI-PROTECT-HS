// Tiny helpers for the ai-prompt-guard command line tool.
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace apgcli {

class Args {
public:
    explicit Args(std::vector<std::string> v) : v_(std::move(v)) {}

    bool flag(const std::string& name) const {
        for (const auto& a : v_) {
            if (a == name) return true;
        }
        return false;
    }
    // --name VALUE or --name=VALUE; returns def if absent.
    std::string get(const std::string& name, const std::string& def = std::string()) const {
        for (size_t i = 0; i < v_.size(); ++i) {
            if (v_[i] == name && i + 1 < v_.size()) return v_[i + 1];
            if (v_[i].size() > name.size() && v_[i].compare(0, name.size(), name) == 0 && v_[i][name.size()] == '=') {
                return v_[i].substr(name.size() + 1);
            }
        }
        return def;
    }
    bool has_value(const std::string& name) const {
        for (size_t i = 0; i < v_.size(); ++i) {
            if (v_[i] == name && i + 1 < v_.size()) return true;
            if (v_[i].size() > name.size() && v_[i].compare(0, name.size(), name) == 0 && v_[i][name.size()] == '=') return true;
        }
        return false;
    }
    std::vector<std::string> get_all(const std::string& name) const {
        std::vector<std::string> out;
        for (size_t i = 0; i < v_.size(); ++i) {
            if (v_[i] == name && i + 1 < v_.size()) out.push_back(v_[i + 1]);
            else if (v_[i].size() > name.size() && v_[i].compare(0, name.size(), name) == 0 && v_[i][name.size()] == '=') {
                out.push_back(v_[i].substr(name.size() + 1));
            }
        }
        return out;
    }
    const std::vector<std::string>& all() const { return v_; }

private:
    std::vector<std::string> v_;
};

// Reads all of stdin (binary).
std::string read_stdin();
// Writes a UTF-8 string to stdout without any newline translation / code-page conversion.
void write_stdout(const std::string& s);
void write_stderr(const std::string& s);

int run_bench(const Args& args);   // cli/bench.cpp

}  // namespace apgcli
