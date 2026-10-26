# Copyright (c) 2023-present The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(voidcoin_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  hex_base.cpp
  hkdf_sha256_32.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  muhash.cpp
  poly1305.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha256_sse4.cpp
  sha3.cpp
  sha512.cpp
  siphash.cpp
  ../support/cleanse.cpp
)

# VC-18: verify the vendored CRYSTALS-Dilithium sources against the pinned
# SHA256 manifest before/whenever the PQ library is (re)built. Any drift or
# tamper of pq/mldsa87/upstream/ fails the build. Provenance + pinned upstream
# commit are recorded in pq/mldsa87/upstream/PROVENANCE.md.
set(PQ_UPSTREAM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pq/mldsa87/upstream)
set(PQ_PROVENANCE_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/pq/mldsa87/VerifyPqProvenance.cmake)
add_custom_target(verify_pq_provenance ALL
  COMMAND ${CMAKE_COMMAND}
    -DPQ_UPSTREAM_DIR=${PQ_UPSTREAM_DIR}
    -P ${PQ_PROVENANCE_SCRIPT}
  COMMENT "Verifying vendored CRYSTALS-Dilithium provenance (VC-18)"
  VERBATIM
)
if(BUILD_TESTS)
  add_test(
    NAME pq_provenance
    COMMAND ${CMAKE_COMMAND}
      -DPQ_UPSTREAM_DIR=${PQ_UPSTREAM_DIR}
      -P ${PQ_PROVENANCE_SCRIPT}
  )
endif()

add_library(voidcoin_mldsa87 STATIC EXCLUDE_FROM_ALL
  pq/mldsa87/mldsa87.cpp
  pq/mldsa87/upstream/ref/fips202.c
  pq/mldsa87/upstream/ref/ntt.c
  pq/mldsa87/upstream/ref/packing.c
  pq/mldsa87/upstream/ref/poly.c
  pq/mldsa87/upstream/ref/polyvec.c
  pq/mldsa87/upstream/ref/randombytes.c
  pq/mldsa87/upstream/ref/reduce.c
  pq/mldsa87/upstream/ref/rounding.c
  pq/mldsa87/upstream/ref/sign.c
  pq/mldsa87/upstream/ref/symmetric-shake.c
)

target_include_directories(voidcoin_mldsa87
  PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/pq/mldsa87/upstream/ref
)

target_compile_definitions(voidcoin_mldsa87
  PRIVATE
    DILITHIUM_MODE=5
)

target_link_libraries(voidcoin_mldsa87
  PRIVATE
    core_interface
)

# Force provenance verification before the PQ library is (re)built (VC-18).
add_dependencies(voidcoin_mldsa87 verify_pq_provenance)

target_link_libraries(voidcoin_crypto
  PRIVATE
    core_interface
)

if(HAVE_SSE41)
  target_compile_definitions(voidcoin_crypto PRIVATE ENABLE_SSE41)
  target_sources(voidcoin_crypto PRIVATE sha256_sse41.cpp)
  set_property(SOURCE sha256_sse41.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS}
  )
endif()

if(HAVE_AVX2)
  target_compile_definitions(voidcoin_crypto PRIVATE ENABLE_AVX2)
  target_sources(voidcoin_crypto PRIVATE sha256_avx2.cpp)
  set_property(SOURCE sha256_avx2.cpp PROPERTY
    COMPILE_OPTIONS ${AVX2_CXXFLAGS}
  )
endif()

if(HAVE_SSE41 AND HAVE_X86_SHANI)
  target_compile_definitions(voidcoin_crypto PRIVATE ENABLE_SSE41 ENABLE_X86_SHANI)
  target_sources(voidcoin_crypto PRIVATE sha256_x86_shani.cpp)
  set_property(SOURCE sha256_x86_shani.cpp PROPERTY
    COMPILE_OPTIONS ${X86_SHANI_CXXFLAGS}
  )
endif()

if(HAVE_ARM_SHANI)
  target_compile_definitions(voidcoin_crypto PRIVATE ENABLE_ARM_SHANI)
  target_sources(voidcoin_crypto PRIVATE sha256_arm_shani.cpp)
  set_property(SOURCE sha256_arm_shani.cpp PROPERTY
    COMPILE_OPTIONS ${ARM_SHANI_CXXFLAGS}
  )
endif()
