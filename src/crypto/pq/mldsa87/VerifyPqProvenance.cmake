# Copyright (c) 2026-present The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Verifies the vendored CRYSTALS-Dilithium (ML-DSA-87) reference sources against
# the pinned SHA256 manifest (audit VC-18). Run at build time as a dependency of
# the voidcoin_mldsa87 library and as the `pq_provenance` CTest. Any drift,
# tamper, missing file, or unlisted extra file fails with FATAL_ERROR.
#
# Invoke with: cmake -DPQ_UPSTREAM_DIR=<dir containing SHA256SUMS> -P VerifyPqProvenance.cmake

if(NOT DEFINED PQ_UPSTREAM_DIR)
  message(FATAL_ERROR "PQ provenance: PQ_UPSTREAM_DIR not set")
endif()

set(_manifest "${PQ_UPSTREAM_DIR}/SHA256SUMS")
if(NOT EXISTS "${_manifest}")
  message(FATAL_ERROR "PQ provenance: manifest not found: ${_manifest}")
endif()

file(STRINGS "${_manifest}" _lines)
set(_listed "")
set(_errors "")

foreach(_line IN LISTS _lines)
  if(_line STREQUAL "")
    continue()
  endif()
  # Each line: "<64-hex>  <relative/path>" (two spaces, sha256sum format).
  if(NOT _line MATCHES "^([0-9a-fA-F]+)  (.+)$")
    list(APPEND _errors "malformed manifest line: '${_line}'")
    continue()
  endif()
  set(_expected "${CMAKE_MATCH_1}")
  set(_rel "${CMAKE_MATCH_2}")
  string(TOLOWER "${_expected}" _expected)
  set(_path "${PQ_UPSTREAM_DIR}/${_rel}")
  list(APPEND _listed "${_rel}")

  if(NOT EXISTS "${_path}")
    list(APPEND _errors "missing vendored file: ${_rel}")
    continue()
  endif()
  file(SHA256 "${_path}" _actual)
  string(TOLOWER "${_actual}" _actual)
  if(NOT _actual STREQUAL _expected)
    list(APPEND _errors "checksum mismatch: ${_rel}\n    expected ${_expected}\n    actual   ${_actual}")
  endif()
endforeach()

# Detect unlisted extra files (drift by addition), excluding the manifest and
# the human-readable provenance doc.
file(GLOB_RECURSE _present RELATIVE "${PQ_UPSTREAM_DIR}" "${PQ_UPSTREAM_DIR}/*")
foreach(_rel IN LISTS _present)
  if(_rel STREQUAL "SHA256SUMS" OR _rel STREQUAL "PROVENANCE.md")
    continue()
  endif()
  list(FIND _listed "${_rel}" _idx)
  if(_idx EQUAL -1)
    list(APPEND _errors "unlisted vendored file (not in SHA256SUMS): ${_rel}")
  endif()
endforeach()

if(_errors)
  string(REPLACE ";" "\n  " _joined "${_errors}")
  message(FATAL_ERROR
    "PQ provenance verification FAILED for vendored CRYSTALS-Dilithium (VC-18).\n"
    "  ${_joined}\n"
    "If this change to the vendored tree is intentional, update SHA256SUMS and "
    "PROVENANCE.md per the regeneration instructions in "
    "src/crypto/pq/mldsa87/upstream/PROVENANCE.md.")
endif()

list(LENGTH _listed _n)
message(STATUS "PQ provenance: verified ${_n} vendored CRYSTALS-Dilithium files against SHA256SUMS")
