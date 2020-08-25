cmake_minimum_required(VERSION 2.8.9)
project (nxflatutils)

include_directories(
 ${CMAKE_SOURCE_DIR}
)

set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_C_FLAGS "-Og -g")
set(CMAKE_C_FLAGS_DEBUG "-Og -g")
set(CMAKE_C_FLAGS_RELEASE "-O0 -g")
set(CMAKE_CXX_FLAGS "-Og -g")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g")

find_library(BFD bfd-multiarch)
find_library(SSL crypto)

add_executable(readnxflat readnxflat.c ${BFD})
target_link_libraries(readnxflat ${BFD})

add_executable(ldnxflat ldnxflat.c ${BFD})
target_link_libraries(ldnxflat ${BFD})

add_executable(mknxflat mknxflat.c ${BFD})
target_link_libraries(mknxflat ${BFD})

add_executable(signnxflat signnxflat.c ${BFD})
target_link_libraries(signnxflat ${SSL})

install(TARGETS readnxflat ldnxflat mknxflat signnxflat DESTINATION bin)
