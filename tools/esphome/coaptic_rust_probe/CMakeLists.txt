idf_component_register()

set(COAPTIC_RUST_TOOLCHAIN "1.97.1")
set(COAPTIC_BUILD_STD_ARGS)
if(IDF_TARGET STREQUAL "esp32c3")
  set(COAPTIC_RUST_TARGET "riscv32imc-unknown-none-elf")
elseif(IDF_TARGET STREQUAL "esp32c6")
  set(COAPTIC_RUST_TARGET "riscv32imac-unknown-none-elf")
elseif(IDF_TARGET STREQUAL "esp32s3")
  set(COAPTIC_RUST_TARGET "xtensa-esp32s3-none-elf")
  set(COAPTIC_RUST_TOOLCHAIN "coaptic-esp-1.97")
  list(APPEND COAPTIC_BUILD_STD_ARGS -Zbuild-std=core)
else()
  message(FATAL_ERROR "Coaptic qualification requires ESP32-C3, ESP32-C6 or ESP32-S3")
endif()

if(NOT EXISTS "${COAPTIC_RUST_MANIFEST}")
  message(FATAL_ERROR "Coaptic Rust manifest is unavailable")
endif()

find_program(COAPTIC_CARGO cargo REQUIRED)
set(COAPTIC_RUST_DIR "${CMAKE_BINARY_DIR}/coaptic-rust")
set(COAPTIC_ARCHIVE "${COAPTIC_RUST_DIR}/${COAPTIC_RUST_TARGET}/release/libcoaptic_esphome_probe.a")
set(COAPTIC_FEATURE_ARGS --features standalone)
if(COAPTIC_OSCORE)
  list(APPEND COAPTIC_FEATURE_ARGS --features oscore)
endif()
if(COAPTIC_NETWORK)
  list(APPEND COAPTIC_FEATURE_ARGS --features network)
endif()

add_custom_target(coaptic_rust_build
  COMMAND "${CMAKE_COMMAND}" -E env "CARGO_TARGET_DIR=${COAPTIC_RUST_DIR}" CARGO_INCREMENTAL=0
    "${COAPTIC_CARGO}" "+${COAPTIC_RUST_TOOLCHAIN}" rustc ${COAPTIC_BUILD_STD_ARGS} --locked --manifest-path "${COAPTIC_RUST_MANIFEST}"
    --release --target "${COAPTIC_RUST_TARGET}" --no-default-features ${COAPTIC_FEATURE_ARGS} --crate-type staticlib
  BYPRODUCTS "${COAPTIC_ARCHIVE}"
  VERBATIM)

add_library(coaptic_rust_probe STATIC IMPORTED GLOBAL)
set_target_properties(coaptic_rust_probe PROPERTIES IMPORTED_LOCATION "${COAPTIC_ARCHIVE}")
add_dependencies(coaptic_rust_probe coaptic_rust_build)
target_link_libraries(${COMPONENT_LIB} INTERFACE coaptic_rust_probe)
