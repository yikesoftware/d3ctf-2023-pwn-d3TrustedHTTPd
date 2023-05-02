project (optee_d3_trusted_core C)

set (SRC host/main.c)
set (HTTPD_SRC "mini_httpd-1.30")


#add_compile_options (
#	-fno-stack-protector
#	-no-pie
#)

add_executable (${PROJECT_NAME} ${SRC})
target_compile_options(${PROJECT_NAME} PRIVATE -O0 -no-pie -fno-stack-protector -mcmodel=large)
target_link_options(${PROJECT_NAME} PRIVATE -O0 -no-pie -mcmodel=large)

add_executable (mini_httpd 
	${HTTPD_SRC}/mini_httpd.c 
	${HTTPD_SRC}/match.c 
	${HTTPD_SRC}/tdate_parse.c)

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)
target_link_libraries (${PROJECT_NAME} PRIVATE pthread)


target_link_libraries (mini_httpd PRIVATE crypt)
#target_link_libraries (mini_httpd PRIVATE openssl)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

install (TARGETS mini_httpd DESTINATION ${CMAKE_INSTALL_BINDIR})
file(COPY mini_httpd-1.30/www DESTINATION /home/eqqie/XDSEC/D3CTF/d3TrustedHttpd/optee_build/out-br/target/var/)