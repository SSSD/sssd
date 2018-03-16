dist_noinst_DATA = \
    SSSD_test_CA.config \
    SSSD_test_CA_key.pem \
    SSSD_test_cert_0001.config \
    SSSD_test_cert_0002.config \
    SSSD_test_cert_key_0001.pem \
    SSSD_test_cert_key_0002.pem \
    $(NULL)

openssl_ca_config = $(srcdir)/SSSD_test_CA.config
openssl_ca_key = $(srcdir)/SSSD_test_CA_key.pem
pwdfile = pwdfile

configs := $(notdir $(wildcard $(srcdir)/SSSD_test_cert_*.config))
ids := $(subst SSSD_test_cert_,,$(basename $(configs)))
certs = $(addprefix SSSD_test_cert_x509_,$(addsuffix .pem,$(ids)))
certs_h = $(addprefix SSSD_test_cert_x509_,$(addsuffix .h,$(ids)))
pubkeys = $(addprefix SSSD_test_cert_pubsshkey_,$(addsuffix .pub,$(ids)))
pubkeys_h = $(addprefix SSSD_test_cert_pubsshkey_,$(addsuffix .h,$(ids)))
pkcs12 = $(addprefix SSSD_test_cert_pkcs12_,$(addsuffix .pem,$(ids)))

if HAVE_NSS
nssdb = p11_nssdb p11_nssdb_2certs
endif

# If openssl is run in parallel there might be conflicts with the serial
.NOTPARALLEL:

ca_all: clean serial SSSD_test_CA.pem $(certs) $(certs_h) $(pubkeys) $(pubkeys_h) $(pkcs12) $(nssdb)

$(pwdfile):
	@echo "12345678" > $@

SSSD_test_CA.pem: $(openssl_ca_key) $(openssl_ca_config) serial
	$(OPENSSL) req -batch -config ${openssl_ca_config} -x509 -new -nodes -key $< -sha256 -days 1024 -set_serial 0 -extensions v3_ca -out $@


SSSD_test_cert_req_%.pem: $(srcdir)/SSSD_test_cert_key_%.pem $(srcdir)/SSSD_test_cert_%.config
	$(OPENSSL) req -new -nodes -key $< -reqexts req_exts -config $(srcdir)/SSSD_test_cert_$*.config -out $@

SSSD_test_cert_x509_%.pem: SSSD_test_cert_req_%.pem $(openssl_ca_config) SSSD_test_CA.pem
	$(OPENSSL) ca -config ${openssl_ca_config} -batch -notext -keyfile $(openssl_ca_key) -in $< -days 200 -extensions usr_cert -out $@

SSSD_test_cert_pkcs12_%.pem: SSSD_test_cert_x509_%.pem $(srcdir)/SSSD_test_cert_key_%.pem $(pwdfile)
	$(OPENSSL) pkcs12 -export -in SSSD_test_cert_x509_$*.pem -inkey $(srcdir)/SSSD_test_cert_key_$*.pem -nodes -passout file:$(pwdfile) -out $@

SSSD_test_cert_pubkey_%.pem: SSSD_test_cert_x509_%.pem
	$(OPENSSL) x509 -in $< -pubkey -noout > $@

SSSD_test_cert_pubsshkey_%.pub: SSSD_test_cert_pubkey_%.pem
	$(SSH_KEYGEN) -i -m PKCS8 -f $< > $@

SSSD_test_cert_x509_%.h: SSSD_test_cert_x509_%.pem
	@echo "#define SSSD_TEST_CERT_$* \""$(shell cat $< |openssl x509 -outform der | base64 -w 0)"\"" > $@

SSSD_test_cert_pubsshkey_%.h: SSSD_test_cert_pubsshkey_%.pub
	@echo "#define SSSD_TEST_CERT_SSH_KEY_$* \""$(shell cut -d' ' -f2 $<)"\"" > $@

# This nss db is used in
# - src/tests/cmocka/test_cert_utils.c (validation only)
# - src/tests/cmocka/test_pam_srv.c
p11_nssdb: SSSD_test_cert_pkcs12_0001.pem SSSD_test_CA.pem $(pwdfile)
	mkdir $@
	$(CERTUTIL) -d sql:./$@ -N --empty-password
	$(CERTUTIL) -d sql:./$@ -A -n 'SSSD test CA' -t CT,CT,CT -a -i SSSD_test_CA.pem
	$(PK12UTIL) -d sql:./$@ -i SSSD_test_cert_pkcs12_0001.pem -w $(pwdfile)

# This nss db is used in
# - src/tests/cmocka/test_pam_srv.c
p11_nssdb_2certs: SSSD_test_cert_pkcs12_0001.pem SSSD_test_cert_pkcs12_0002.pem SSSD_test_CA.pem $(pwdfile)
	mkdir $@
	$(CERTUTIL) -d sql:./$@ -N --empty-password
	$(CERTUTIL) -d sql:./$@ -A -n 'SSSD test CA' -t CT,CT,CT -a -i SSSD_test_CA.pem
	$(PK12UTIL) -d sql:./$@ p11_nssdb -i SSSD_test_cert_pkcs12_0001.pem -w $(pwdfile)
	$(PK12UTIL) -d sql:./$@ p11_nssdb -i SSSD_test_cert_pkcs12_0002.pem -w $(pwdfile)

CLEANFILES = \
    index.txt  index.txt.attr \
    index.txt.attr.old  index.txt.old \
    serial  serial.old  \
    SSSD_test_CA.pem $(pwdfile) \
    $(certs) $(certs_h) $(pubkeys) $(pubkeys_h) $(pkcs12) \
    $(NULL)

clean-local:
	rm -rf newcerts
	rm -rf p11_nssdb
	rm -rf p11_nssdb_2certs

serial: clean
	touch index.txt
	touch index.txt.attr
	mkdir newcerts
	echo -n 01 > serial
