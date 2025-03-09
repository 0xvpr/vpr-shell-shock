cmake_minimum_required( VERSION 3.15 )

project(
  vpr-shell-shock
    VERSION 1.1.0
    DESCRIPTION "vpr-shell-shock: single-header library for x86/64 windows position independent shellcode generation"
    LANGUAGES C CXX
)

set( CMAKE_C_STANDARD             99 )
set( CMAKE_C_STANDARD_REQUIRED    ON )
set( CMAKE_C_EXTENSIONS          OFF )

set( CMAKE_CXX_STANDARD           17 )
set( CMAKE_CXX_STANDARD_REQUIRED  ON )
set( CMAKE_CXX_EXTENSIONS        OFF )

include(GNUInstallDirs)

add_library(vpr-shell-shock INTERFACE)

target_include_directories(
  vpr-shell-shock INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>    # When building from this source dir
    $<INSTALL_INTERFACE:include>                              # When installed on a system
)

add_library(vpr-shell-shock::shell-shock ALIAS vpr-shell-shock)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
  TARGETS vpr-shell-shock
  EXPORT vpr-shell-shock-targets
)

install(
  EXPORT vpr-shell-shock-targets
  FILE vpr-shell-shock-targets.cmake
  NAMESPACE vpr-shell-shock::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vpr-shell-shock
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/vpr-shell-shock-config-version.cmake"
  VERSION       ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/vpr-shell-shock-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/vpr-shell-shock-config.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vpr-shell-shock"
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/vpr-shell-shock-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/vpr-shell-shock-config-version.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vpr-shell-shock
)

option(VPR_SHELL_BUILD_TESTS "Build tests" OFF)
if(VPR_SHELL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

include(CPack)
