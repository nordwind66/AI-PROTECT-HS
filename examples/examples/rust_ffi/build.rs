// Tells cargo where the shared library lives: AI_PROMPT_GUARD_LIB_DIR=<directory containing the .so / .lib>.
fn main() {
    println!("cargo:rerun-if-env-changed=AI_PROMPT_GUARD_LIB_DIR");
    if let Ok(dir) = std::env::var("AI_PROMPT_GUARD_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
    }
    println!("cargo:rustc-link-lib=dylib=ai_prompt_guard");
}
