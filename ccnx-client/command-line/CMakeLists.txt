set(CCNX_CLIENT_SRC
          ccnx-client.c
          ccnxPortalClient_About.c 
  )

set(CCNX_CLIENT_LOOP_SRC
          ccnx-client-loop.c
          ccnxPortalClient_About.c 
  )

set(CCNX_SERVER_SRC 
          ccnx-server.c 
          ccnxPortalServer_About.c 
  )

#set(OTOCN_CAMERA_SERVER_SRC 
#          otocn-camera-server.c 
#  )



add_executable(ccnx-client ${CCNX_CLIENT_SRC})
target_link_libraries(ccnx-client ${CCNX_LINK_LIBRARIES})

add_executable(ccnx-client-loop ${CCNX_CLIENT_LOOP_SRC})
target_link_libraries(ccnx-client-loop ${CCNX_LINK_LIBRARIES})

add_executable(ccnx-server ${CCNX_SERVER_SRC})
target_link_libraries(ccnx-server ${CCNX_LINK_LIBRARIES})

#add_executable(otocn-camera-server ${OTOCN_CAMERA_SERVER_SRC})
#target_link_libraries(otocn-camera-server ${CCNX_LINK_LIBRARIES})

install(TARGETS ccnx-client ccnx-client-loop ccnx-server RUNTIME DESTINATION bin )
#install(TARGETS ccnx-client ccnx-server otocn-camera-server RUNTIME DESTINATION bin )
