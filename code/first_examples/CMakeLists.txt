cmake_minimum_required(VERSION 3.7)
project(DynamoBranchTracker)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build. Make sure to specify -DDynamoRIO_DIR")
endif()

add_library(dynamo SHARED dynamo.c)

configure_DynamoRIO_client(dynamo)

use_DynamoRIO_extension(dynamo drmgr)

