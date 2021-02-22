#------------------------------------------------------------------------------
# Top-level CMake file for FISCO-BCOS.
# ------------------------------------------------------------------------------
# Copyright (C) 2021 FISCO BCOS.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.10)
set(BCOS_FRAMEWORK bcos-framework)

set(BCOS_CRYPTO_LIB_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE PATH "The path for the library")
set(BCOS_CRYPTO_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${BCOS_CRYPTO_CMAKE_DIR})

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")

project(bcos-crypto VERSION "3.0")
# Suffix like "-rc1" e.t.c. to append to versions wherever needed.
set(VERSION_SUFFIX "")

# basic setting

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/${BCOS_FRAMEWORK}/cmake)
include(Options)
configure_project()
include(CompilerSettings)

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY ON)

# install dependencies
#include(ProjectBcosFramework)

include_directories("${CMAKE_SOURCE_DIR}")

add_subdirectory(${BCOS_FRAMEWORK})
add_subdirectory(libproto)

if (TESTS)
    enable_testing()
    set(CTEST_OUTPUT_ON_FAILURE TRUE)
    add_subdirectory(test)
endif()

find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
# Requirements: doxygen graphviz
  set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/.Doxyfile.in)
  set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
  configure_file(${doxyfile_in} ${doxyfile} @ONLY)
# Add doc target
add_custom_target(doc COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
                       WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                       COMMENT "Generating documentation with Doxygen..." VERBATIM)
elseif()
  message(WARNING "Doxygen is needed to build the documentation. Please install doxygen and graphviz")
endif()
