cmake_minimum_required(VERSION 3.10)
project(ipflow_extractor)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# 包含头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 源文件
set(SOURCES
    src/pcap_reader.cpp
    src/feature_extractor.cpp
    src/sliding_window.cpp
    src/csv_writer.cpp
    src/main.cpp
)

# 生成可执行文件
add_executable(ipflow_extractor ${SOURCES})

# 安装规则
install(TARGETS ipflow_extractor DESTINATION bin)
