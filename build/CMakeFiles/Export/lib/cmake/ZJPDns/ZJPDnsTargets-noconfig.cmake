#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "ZJPDns::zjpdns_shared" for configuration ""
set_property(TARGET ZJPDns::zjpdns_shared APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(ZJPDns::zjpdns_shared PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libzjpdns.so.1.0.0"
  IMPORTED_SONAME_NOCONFIG "libzjpdns.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS ZJPDns::zjpdns_shared )
list(APPEND _IMPORT_CHECK_FILES_FOR_ZJPDns::zjpdns_shared "${_IMPORT_PREFIX}/lib/libzjpdns.so.1.0.0" )

# Import target "ZJPDns::zjpdns_static" for configuration ""
set_property(TARGET ZJPDns::zjpdns_static APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(ZJPDns::zjpdns_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CXX"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libzjpdns.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS ZJPDns::zjpdns_static )
list(APPEND _IMPORT_CHECK_FILES_FOR_ZJPDns::zjpdns_static "${_IMPORT_PREFIX}/lib/libzjpdns.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
