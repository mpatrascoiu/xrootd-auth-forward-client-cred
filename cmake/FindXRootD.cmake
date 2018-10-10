# Try to find XRootD
# Once done, this will define
#
# XROOTD_FOUND       - system has XRootD
# XROOTD_INCLUDE_DIR - the XRootD include directory
# XROOTD_LIB_DIR     - the XRootD library directory
# XROOTD_PRIVATE_INDCLUDE_DIR - the XRootD private include directory
#
# XROOTD_DIR may be defined as a hint for where to look

include( FindPackageHandleStandardArgs )

find_path(
  XROOTD_INCLUDE_DIR
  NAMES XrdVersion.hh
  HINTS ${XROOTD_DIR} $ENV{XROOTD_DIR} /usr /opt/xrootd/
  PATH_SUFFIXES include/xrootd )

find_path(
  XROOTD_PRIVATE_INCLUDE_DIR
  NAMES XrdSecsss/XrdSecsssID.hh
  HINTS ${XROOTD_DIR} $ENV{XROOTD_DIR} /usr /opt/xrootd/
  PATH_SUFFIXES include/xrootd/private )

find_library(
  XROOTD_UTILS
  NAMES XrdUtils
  HINTS ${XROOTD_DIR} $ENV{XROOTD_DIR} /usr /opt/xrootd/
  PATH_SUFFIXES lib lib64 )

find_library(
  XROOTD_SECSSS
  NAMES XrdSecsss-4
  HINTS
  ${XROOTD_DIR} $ENV{XROOTD_DIR} /usr /opt/xrootd/
  PATH_SUFFIXES lib lib64 )

get_filename_component(
  XROOTD_LIB_DIR ${XROOTD_UTILS}
  PATH )


find_package_handle_standard_args(
  XRootD
  DEFAULT_MSG
  XROOTD_LIB_DIR
  XROOTD_INCLUDE_DIR
  XROOTD_PRIVATE_INCLUDE_DIR )
