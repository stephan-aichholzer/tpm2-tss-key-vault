cmake_minimum_required(VERSION 3.16)
project(tpm_example)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL for crypto operations
find_package(OpenSSL REQUIRED)

# TSS2 for TPM encrypted sessions
find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2 REQUIRED
    tss2-esys
    tss2-rc
    tss2-tctildr
    tss2-mu
)

# Basic TPM example (OpenSSL provider only - no encrypted session)
add_executable(tpm_example tpm_example.cpp)
target_link_libraries(tpm_example OpenSSL::SSL OpenSSL::Crypto)

# KeyVault with encrypted TPM sessions
add_executable(key_vault_example
    key_vault_example.cpp
    key_vault.cpp
    tss_session.cpp
    process_hardening.cpp
)
target_include_directories(key_vault_example PRIVATE ${TSS2_INCLUDE_DIRS})
target_link_libraries(key_vault_example
    OpenSSL::SSL
    OpenSSL::Crypto
    ${TSS2_LIBRARIES}
)
