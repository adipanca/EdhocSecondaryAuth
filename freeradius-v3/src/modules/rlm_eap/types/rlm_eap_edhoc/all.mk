TARGET := rlm_eap_edhoc
SOURCES := rlm_eap_edhoc.c
TGT_PREREQS := libfreeradius-server.a
TGT_LDLIBS := -lcrypto
