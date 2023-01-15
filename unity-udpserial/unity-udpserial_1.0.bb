#
# Unity extra/common files, used and shared by different packages
#

SUMMARY = "Unity extra/common files"
SECTION = "system"
LICENSE = "CLOSED"

DEPENDS += "openssl"
inherit cmake

SRC_URI += "file://udp_serial.cpp \
            file://CMakeLists.txt \
            "

FILES:udpserial += "${bindir}/udpserial"
B = "${S}/build"

#unset default packages
FILES:${PN} += "${bindir}/udpserial"
FILES:${PN}-dev = ""
FILES:${PN}-staticdev = ""
# a deploy task for artifacts to be deployed


inherit deploy
addtask do_deploy after do_install

do_deploy() {
}

# NOTE: workaround to avoid packaging issue since removing usr/local and usr/local/bin.
FILES:${PN}-dev += "${exec_prefix}/local"
FILES:${PN}-dev += "${exec_prefix}/local/bin"

do_install:append() {
   #This creates the directory inside image folder with name usr/bin
   install -d ${D}${bindir}
   #chown root:root ${D}${bindir}
   #This copies the binary into <image>/usr/bin
   install ${B}/udpserial ${D}${bindir}
}

do_configure() {
    mkdir -p ${B}
    cd ${B}
    cmake ../..
}

do_compile() {
    cd ${B}
    oe_runmake
}


