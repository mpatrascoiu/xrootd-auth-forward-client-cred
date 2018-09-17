#-------------------------------------------------------------------------------
# Project description
#-------------------------------------------------------------------------------

cmake_minimum_required( VERSION 2.6 )
project( AuthForwardClientId )

set( CMAKE_INSTALL_PREFIX /usr )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/cmake )

set( LIB_INSTALL_DIR lib64 )

add_subdirectory( src )
