file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

add_library(proto ${SRC_LIST} ${HEADERS})

target_compile_options(proto PRIVATE -Wno-error -Wno-unused-variable)
find_package(Boost CONFIG REQUIRED iostreams log filesystem)
find_package(bcos-framework CONFIG REQUIRED)
target_link_libraries(proto PUBLIC Boost::iostreams Boost::log Boost::filesystem bcos-framework::bcos_framework_utilities)