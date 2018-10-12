find_package( XRootD REQUIRED )

add_library(
  AuthForwardClientId SHARED
  AuthForwardClientId.cc AuthForwardClientId.hh )

include_directories(
  ${XROOTD_INCLUDE_DIR}
  ${XROOTD_PRIVATE_INCLUDE_DIR} )

add_definitions(
  -D_LARGEFILE_SOURCE
  -D_LARGEFILE64_SOURCE
  -D_FILE_OFFSET_BITS=64 )

target_link_libraries( AuthForwardClientId )

if( Linux )
    set_target_properties(
      AuthForwardClientId
      PROPERTIES
      CLEAN_DIRECT_OUTPUT 1 )
endif( Linux )

install(
  TARGETS AuthForwardClientId
  LIBRARY DESTINATION ${LIB_INSTALL_DIR} )
