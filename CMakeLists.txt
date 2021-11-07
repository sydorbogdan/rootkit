cmake_minimum_required(VERSION 3.15)


set(PROJECT_NAME rootkit)
project(${PROJECT_NAME} C CXX)

set(CMAKE_CXX_STANDARD 20)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif ()


include_directories(include)


add_executable(${PROJECT_NAME} src/main.cpp)


set_target_properties(${PROJECT_NAME}
		PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)