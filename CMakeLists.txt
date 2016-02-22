CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(amd C)

ADD_DEFINITIONS("-DSHARE_PREFIX=\"${SHARE_INSTALL_PREFIX}/aul\"")
IF (with_wayland)
       ADD_DEFINITIONS("-DWAYLAND")
ENDIF (with_wayland)
IF (with_x11)
       ADD_DEFINITIONS("-DX11")
ENDIF (with_x11)

# Set required packages
INCLUDE(FindPkgConfig)

SET(AMD_PKG_CHECK_MODULES dlog rua aul glib-2.0 gio-2.0 vconf pkgmgr-info pkgmgr bundle libsystemd-daemon cynara-client cynara-creds-socket cynara-session cert-svc-vcore libtzplatform-config xkbcommon sensor security-manager)
IF (with_wayland)
	pkg_check_modules(pkgs REQUIRED  ${AMD_PKG_CHECK_MODULES} wayland-client tizen-extension-client ecore-wayland wayland-tbm-client)
ENDIF (with_wayland)
IF (with_x11)
	pkg_check_modules(pkgs REQUIRED  ${AMD_PKG_CHECK_MODULES} )
ENDIF (with_x11)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# Compiler flags
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fpic")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Werror")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")
SET(CMAKE_SKIP_BUILD_RPATH true)
# Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_EXECUTABLE(amd
	src/amd_main.c
	src/amd_request.c
	src/amd_appinfo.c
	src/amd_launch.c
	src/amd_status.c
	src/amd_app_com.c
	src/amd_app_group.c
	src/amd_cynara.c
	src/amd_socket.c
	src/amd_share.c
	src/amd_splash_screen.c
	src/amd_input.c
	)
SET_TARGET_PROPERTIES(amd PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS} -fPIE")
TARGET_LINK_LIBRARIES(amd ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS amd DESTINATION bin)


