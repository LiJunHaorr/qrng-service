cmake_minimum_required(VERSION 3.16)
project(qrng-service C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(QRNG_WITH_QUANTIS "Build the Quantis USB backend (needs the Quantis SDK)" ON)

find_package(Threads REQUIRED)

# OBJECT 库（而非 STATIC）：后端靠 GCC constructor 自注册，
# 静态归档里未被引用的 .o 不会被链接器拉入，构造函数就不会执行
# （Linux/MinGW 都会踩这个坑）。OBJECT 库的对象总是整体链接进
# 可执行文件，自注册才可靠。
add_library(qrng_core OBJECT
  src/core.c
  src/condition/condition.c
  src/condition/sha256.c
  src/drbg/aes.c
  src/drbg/ctr_drbg.c
  src/health/health.c
  src/source/mock_det.c
  src/source/mock_stuck.c
  src/source/mock_biased.c
  src/source/file.c
)
target_include_directories(qrng_core PUBLIC include)
target_link_libraries(qrng_core PUBLIC Threads::Threads)
if(NOT WIN32)
  # health.c 的二项分布分位数用 lgamma
  target_link_libraries(qrng_core PUBLIC m)
endif()

if(QRNG_WITH_QUANTIS)
  # Quantis SDK 按动手清单装在 /opt/idq-quantis；不同路径就：
  #   cmake -B build -DQUANTIS_ROOT=/你的/路径
  set(QUANTIS_ROOT "/opt/idq-quantis" CACHE PATH "Quantis SDK install prefix")
  find_path(QUANTIS_INCLUDE_DIR Quantis.h
            PATHS "${QUANTIS_ROOT}/include" NO_DEFAULT_PATH REQUIRED)
  find_library(QUANTIS_LIBRARY NAMES Quantis
               PATHS "${QUANTIS_ROOT}/lib64" "${QUANTIS_ROOT}/lib"
               NO_DEFAULT_PATH REQUIRED)
  target_sources(qrng_core PRIVATE src/source/quantis.c)
  target_compile_definitions(qrng_core PRIVATE QRNG_WITH_QUANTIS)
  target_include_directories(qrng_core PRIVATE "${QUANTIS_INCLUDE_DIR}")
  target_link_libraries(qrng_core PRIVATE ${QUANTIS_LIBRARY})
  # Quantis Unix 后端基于 libusb-1.0；SDK 装出的是静态库时必须显式带上
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBUSB1 QUIET IMPORTED_TARGET libusb-1.0)
  endif()
  if(TARGET PkgConfig::LIBUSB1)
    target_link_libraries(qrng_core PRIVATE PkgConfig::LIBUSB1)
  else()
    find_library(LIBUSB1_LIBRARY NAMES usb-1.0 libusb-1.0)
    if(NOT LIBUSB1_LIBRARY)
      message(FATAL_ERROR "libusb-1.0 not found (sudo apt install libusb-1.0-0-dev)")
    endif()
    target_link_libraries(qrng_core PRIVATE ${LIBUSB1_LIBRARY})
  endif()
endif()

add_executable(qrng-cli apps/qrng_cli.c apps/opts.c)
target_link_libraries(qrng-cli PRIVATE qrng_core)

# v1 起有单测：ctest --test-dir build --output-on-failure
enable_testing()
add_executable(test_health tests/test_health.c)
target_link_libraries(test_health PRIVATE qrng_core)
add_test(NAME health COMMAND test_health)

add_executable(test_condition tests/test_condition.c)
target_link_libraries(test_condition PRIVATE qrng_core)
add_test(NAME condition COMMAND test_condition)

add_executable(test_drbg tests/test_drbg.c)
target_link_libraries(test_drbg PRIVATE qrng_core)
add_test(NAME drbg COMMAND test_drbg)

# v4 服务化：守护进程 + Unix socket/TCP 客户端（POSIX 专用，
# fork/setsid/AF_UNIX 在 Windows 上不可用）
if(NOT WIN32)
  add_executable(qrng-server apps/qrng_server.c apps/opts.c)
  target_link_libraries(qrng-server PRIVATE qrng_core)

  add_executable(qrng-fetch apps/qrng_fetch.c)

  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME service
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service.py
                     $<TARGET_FILE:qrng-server> $<TARGET_FILE:qrng-fetch>)
  endif()

  # 应用层 demo（消费端）：ML-KEM keygen 吃本项目链的随机数。
  # 需要 liboqs（demo 默认用 pqcvm03 上 pqc-lab 的 0.16 构建；
  # 别的机器传 -DOQS_ROOT=<liboqs build/install 目录>）。
  option(QRNG_WITH_OQS "Build the ML-KEM keygen demo app (needs liboqs)" ON)
  if(QRNG_WITH_OQS)
    set(OQS_ROOT "/home/pqc/pqc-lab/liboqs/build" CACHE PATH "liboqs build or install prefix")
    find_path(OQS_INCLUDE_DIR oqs/oqs.h
              PATHS "${OQS_ROOT}/include" NO_DEFAULT_PATH)
    find_library(OQS_LIBRARY NAMES oqs
                 PATHS "${OQS_ROOT}/lib" NO_DEFAULT_PATH)
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
      # liboqs 的 sha2 后端走 OpenSSL EVP，需要 libcrypto
      find_package(OpenSSL REQUIRED)
      add_executable(qrng-keygen apps/qrng_keygen.c apps/opts.c apps/svc_client.c)
      target_include_directories(qrng-keygen PRIVATE apps ${OQS_INCLUDE_DIR})
      target_link_libraries(qrng-keygen PRIVATE qrng_core ${OQS_LIBRARY}
                                              OpenSSL::Crypto)
      message(STATUS "qrng-keygen: liboqs found at ${OQS_ROOT}")
      if(Python3_Interpreter_FOUND)
        add_test(NAME keygen
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_keygen.py
                         $<TARGET_FILE:qrng-keygen> $<TARGET_FILE:qrng-server>)
      endif()
    else()
      message(STATUS "qrng-keygen: liboqs not found (set -DOQS_ROOT=...), app skipped")
    endif()
  endif()
endif()