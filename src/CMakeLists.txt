find_package( XRootD REQUIRED )

add_library( AuthForwardClientCred SHARED
             AuthForwardClientCred.cc AuthForwardClientCred.hh
)

include_directories( ${XROOTD_INCLUDE_DIR} )

add_definitions( -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 )

target_link_libraries( AuthForwardClientCred )

if( Linux )
    set_target_properties( AuthForwardClientCred PROPERTIES
      CLEAN_DIRECT_OUTPUT 1
    )
endif( Linux )

install( TARGETS AuthForwardClientCred LIBRARY DESTINATION ${LIB_INSTALL_DIR} )
