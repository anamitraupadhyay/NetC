cmake_minimum_required(VERSION 3.10)
project(onvif_fakecamera C CXX)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set C++ standard for network_config subproject
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Enable pthread support
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

# --- Build the network_config library (NetPlan Manager C API) ---
add_subdirectory(network_config)

# --- Serial number generator (runs once to create vtpl_cnf/vsaas_cloud_config.cnf) ---
add_executable(serial_gen serial.c)

# Ensure cnf directory exists and generate the serial if not already present.
# serial_gen has a built-in safety net: if the ID already exists in the file, it exits immediately.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/vtpl_cnf/vsaas_cloud_config.cnf
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/vtpl_cnf
    COMMAND serial_gen
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS serial_gen
    COMMENT "Generating serial number (skips if already present)"
)
add_custom_target(generate_serial ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/vtpl_cnf/vsaas_cloud_config.cnf
)

# --- Main ONVIF server ---
add_executable(m main.c)

# Main server depends on serial generation
add_dependencies(m generate_serial)

# Include directories for header files
target_include_directories(m PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(m PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    netplan_config
)