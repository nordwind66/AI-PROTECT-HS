# CMake generated Testfile for 
# Source directory: /home/wangyy/ai-rule/AI防护规则
# Build directory: /home/wangyy/ai-rule/AI防护规则
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(cpp_unit "/home/wangyy/ai-rule/AI防护规则/bin/apg_tests")
set_tests_properties(cpp_unit PROPERTIES  WORKING_DIRECTORY "/home/wangyy/ai-rule/AI防护规则" _BACKTRACE_TRIPLES "/home/wangyy/ai-rule/AI防护规则/CMakeLists.txt;137;add_test;/home/wangyy/ai-rule/AI防护规则/CMakeLists.txt;0;")
add_test(python_unit "/root/miniconda3/bin/python3" "-X" "utf8" "-m" "unittest" "discover" "-s" "tests/python" "-v")
set_tests_properties(python_unit PROPERTIES  WORKING_DIRECTORY "/home/wangyy/ai-rule/AI防护规则" _BACKTRACE_TRIPLES "/home/wangyy/ai-rule/AI防护规则/CMakeLists.txt;141;add_test;/home/wangyy/ai-rule/AI防护规则/CMakeLists.txt;0;")
add_test(e2e_compile_scan "/root/miniconda3/bin/python3" "-X" "utf8" "tests/e2e/run_e2e.py" "--cli" "/home/wangyy/ai-rule/AI防护规则/bin/ai-prompt-guard" "--workdir" "/home/wangyy/ai-rule/AI防护规则/e2e" "--backend" "hyperscan" "--clean" "--lib" "/home/wangyy/ai-rule/AI防护规则/bin/libai_prompt_guard.so.1.0.0" "--examples-dir" "/home/wangyy/ai-rule/AI防护规则/bin")
set_tests_properties(e2e_compile_scan PROPERTIES  TIMEOUT "1800" WORKING_DIRECTORY "/home/wangyy/ai-rule/AI防护规则" _BACKTRACE_TRIPLES "/home/wangyy/ai-rule/AI防护规则/CMakeLists.txt;150;add_test;/home/wangyy/ai-rule/AI防护规则/CMakeLists.txt;0;")
subdirs("examples")
