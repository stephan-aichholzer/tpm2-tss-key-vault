cmake_minimum_required(VERSION 3.16)
project(tpm_example)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(tpm_example tpm_example.cpp)
target_link_libraries(tpm_example OpenSSL::SSL OpenSSL::Crypto)

add_executable(key_vault_example key_vault_example.cpp key_vault.cpp process_hardening.cpp)
target_link_libraries(key_vault_example OpenSSL::SSL OpenSSL::Crypto)
