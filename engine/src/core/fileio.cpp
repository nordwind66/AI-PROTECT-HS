#include "fileio.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <system_error>

namespace apg {

namespace fs = std::filesystem;

namespace {
fs::path to_path(const std::string& u8) { return fs::u8path(u8); }
std::string to_utf8(const fs::path& p) { return p.u8string(); }
}  // namespace

bool FileReader::open(const std::string& utf8_path, std::string* error) {
    in_.open(to_path(utf8_path), std::ios::binary);
    if (!in_.is_open()) {
        if (error) *error = "cannot open " + utf8_path;
        return false;
    }
    return true;
}

size_t FileReader::read(void* buf, size_t n) {
    in_.read(static_cast<char*>(buf), static_cast<std::streamsize>(n));
    const std::streamsize got = in_.gcount();
    if (in_.bad()) failed_ = true;
    return got > 0 ? static_cast<size_t>(got) : 0;
}

bool read_file(const std::string& utf8_path, std::string* out, std::string* error, size_t max_bytes) {
    std::error_code ec;
    const fs::path p = to_path(utf8_path);
    const auto size = fs::file_size(p, ec);
    if (ec) {
        if (error) *error = "cannot stat " + utf8_path + ": " + ec.message();
        return false;
    }
    if (static_cast<unsigned long long>(size) > static_cast<unsigned long long>(max_bytes)) {
        if (error) *error = utf8_path + " is larger than the allowed " + std::to_string(max_bytes) + " bytes";
        return false;
    }
    FileReader r;
    if (!r.open(utf8_path, error)) return false;
    out->clear();
    out->reserve(static_cast<size_t>(size));
    char buf[65536];
    for (;;) {
        const size_t n = r.read(buf, sizeof(buf));
        if (n == 0) break;
        out->append(buf, n);
    }
    if (r.failed()) {
        if (error) *error = "read error on " + utf8_path;
        return false;
    }
    return true;
}

bool write_file_atomic(const std::string& utf8_path, const std::string& data, std::string* error) {
    const fs::path target = to_path(utf8_path);
    const long long stamp = static_cast<long long>(std::chrono::steady_clock::now().time_since_epoch().count());
    fs::path tmp = target;
    tmp += ".tmp" + std::to_string(stamp);
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            if (error) *error = "cannot create " + to_utf8(tmp);
            return false;
        }
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        out.flush();
        if (!out.good()) {
            if (error) *error = "write error on " + to_utf8(tmp);
            out.close();
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, target, ec);
    if (ec) {
        // On Windows rename fails if the target exists with some handles open; try remove + rename.
        std::error_code ec2;
        fs::remove(target, ec2);
        ec.clear();
        fs::rename(tmp, target, ec);
    }
    if (ec) {
        if (error) *error = "cannot rename " + to_utf8(tmp) + " to " + utf8_path + ": " + ec.message();
        std::error_code ignore;
        fs::remove(tmp, ignore);
        return false;
    }
    return true;
}

bool path_exists(const std::string& utf8_path) {
    std::error_code ec;
    return fs::exists(to_path(utf8_path), ec);
}

bool make_dirs(const std::string& utf8_path, std::string* error) {
    std::error_code ec;
    fs::create_directories(to_path(utf8_path), ec);
    if (ec) {
        if (error) *error = "cannot create directory " + utf8_path + ": " + ec.message();
        return false;
    }
    return true;
}

bool remove_all_path(const std::string& utf8_path, std::string* error) {
    std::error_code ec;
    fs::remove_all(to_path(utf8_path), ec);
    if (ec) {
        if (error) *error = "cannot remove " + utf8_path + ": " + ec.message();
        return false;
    }
    return true;
}

bool rename_path(const std::string& from_utf8, const std::string& to_utf8, std::string* error) {
    std::error_code ec;
    fs::rename(to_path(from_utf8), to_path(to_utf8), ec);
    if (ec) {
        if (error) *error = "cannot rename " + from_utf8 + " to " + to_utf8 + ": " + ec.message();
        return false;
    }
    return true;
}

bool list_directory(const std::string& utf8_path, std::vector<std::string>* names, std::string* error) {
    std::error_code ec;
    names->clear();
    for (fs::directory_iterator it(to_path(utf8_path), ec), end; !ec && it != end; it.increment(ec)) {
        names->push_back(to_utf8(it->path().filename()));
    }
    if (ec) {
        if (error) *error = "cannot list " + utf8_path + ": " + ec.message();
        return false;
    }
    return true;
}

std::string path_dir(const std::string& utf8_path) { return to_utf8(to_path(utf8_path).parent_path()); }

std::string path_join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    return to_utf8(to_path(a) / to_path(b));
}

std::string path_filename(const std::string& utf8_path) { return to_utf8(to_path(utf8_path).filename()); }

std::string current_dir_utf8() {
    std::error_code ec;
    const fs::path p = fs::current_path(ec);
    return ec ? std::string() : to_utf8(p);
}

}  // namespace apg
