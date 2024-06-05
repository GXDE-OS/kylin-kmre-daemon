install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/cn.kylinos.Kmre.conf
    DESTINATION ${DIR_ETC}/dbus-1/system.d/)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/cn.kylinos.Kmre.service
    DESTINATION ${DIR_SHARE}/dbus-1/system-services/)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/kylin-kmre-daemon.service
    DESTINATION ${DIR_SYSTEMD}/system/)

#install(
#    FILES ${CMAKE_CURRENT_SOURCE_DIR}/kylin-kmre-load-image.service
#    DESTINATION ${DIR_SYSTEMD}/system/)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/kmre-env.sh
    DESTINATION ${DIR_ETC}/profile.d/)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/99-kmre-rsyslog.conf
    DESTINATION ${DIR_ETC}/rsyslog.d/)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/kmre-logrotate
    DESTINATION ${DIR_ETC}/logrotate.d/)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/99-kmre.rules
    DESTINATION ${DIR_ETC}/udev/rules.d/)
