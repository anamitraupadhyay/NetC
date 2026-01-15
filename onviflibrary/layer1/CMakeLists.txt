find_package(LibXml2 REQUIRED)
add_executable(my_program clientudp.c serverudp.c)
target_link_libraries(my_program PUBLIC LibXml2::LibXml2)
