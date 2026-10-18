// Small cross-platform file helpers. All paths are UTF-8 strings (also on Windows, where they are converted
// to wide paths by std::filesystem::u8path).
#pragma once

#include <cstddef>
#include <fstream>
#include <string>
#include <vector>

namespace apg {

class FileReader {
public:
    FileReader() : failed_(false) {}
    bool open(const std::string& utf8_path, std::string* error);
    // Returns the number of bytes read (0 at end of file or on error; check failed()).
    size_t read(void* buf, size_t n);
    bool failed() const { return failed_; }

private:
    std::ifstream in_;
    bool failed_;
};

// Reads the whole file (refuses files larger than max_bytes).
bool read_file(const std::string& utf8_path, std::string* out, std::string* error, size_t max_bytes = (size_t)1 << 30);
// Writes data to a temporary file in the same directory and renames it over the target (atomic replace).
bool write_file_atomic(const std::string& utf8_path, const std::string& data, std::string* error);
bool path_exists(const std::string& utf8_path);
bool make_dirs(const std::string& utf8_path, std::string* error);
bool remove_all_path(const std::string& utf8_path, std::string* error);                    // file or directory tree
bool rename_path(const std::string& from_utf8, const std::string& to_utf8, std::string* error);
bool list_directory(const std::string& utf8_path, std::vector<std::string>* names, std::string* error);  // file names only
std::string path_dir(const std::string& utf8_path);                         // "" if there is no directory part
std::string path_join(const std::string& a, const std::string& b);
std::string path_filename(const std::string& utf8_path);
std::string current_dir_utf8();

}  // namespace apg
