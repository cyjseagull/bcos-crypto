file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

add_library(proto ${SRC_LIST} ${HEADERS})

target_include_directories(proto SYSTEM BEFORE PUBLIC ${BOOST_INCLUDE_DIR})
# set_source_files_properties(${SRC_LIST} ${HEADERS} PROPERTIES COMPILE_FLAGS -Wno-unused-function)
target_compile_options(proto PRIVATE -Wno-error -Wno-unused-variable)

target_link_libraries(proto PUBLIC Boost::iostreams)
