TARGETNAME	:= rlm_eap_edhoc

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c

# Shared EAP-EDHOC method-4 core (built separately under EdhocSecondaryAuth/edhoc4)
EDHOC4_DIR	:= $(top_srcdir)/../edhoc4

SRC_CFLAGS	:= -I$(EDHOC4_DIR)
SRC_INCDIRS	:= ../../ ../../libeap/
TGT_LDLIBS	:= $(EDHOC4_DIR)/libedhoc4.a -lsodium
TGT_PREREQS	:= libfreeradius-eap.a
