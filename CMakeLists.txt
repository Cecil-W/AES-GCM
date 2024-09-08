cmake_minimum_required(VERSION 3.10)
project(AES128)


set(SRC_FILES  sources/aes-128.c sources/gcm.c main.c)


include_directories(include)

add_executable(${PROJECT_NAME} ${SRC_FILES})
