dist_noinst_DATA = \
    SSSD_test_CA.config \
    SSSD_test_CA_key.pem \
    SSSD_test_cert_0001.config \
    SSSD_test_cert_0002.config \
    SSSD_test_cert_0003.config \
    SSSD_test_cert_key_0001.pem \
    SSSD_test_cert_key_0002.pem \
    SSSD_test_cert_key_0003.pem \
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
extra = p11_nssdb p11_nssdb_2certs
else
extra = softhsm2_none softhsm2_one softhsm2_two
endif

# If openssl is run in parallel there might be conflicts with the serial
.NOTPARALLEL:

ca_all: clean serial SSSD_test_CA.pem $(certs) $(certs_h) $(pubkeys) $(pubkeys_h) $(pkcs12) $(extra)

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

# The softhsm2 PKCS#11 setups are used in
# - src/tests/cmocka/test_pam_srv.c
# if SSSD is build with OpenSSL/libcrypto
softhsm2_none: softhsm2_none.conf
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free

softhsm2_none.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_none" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_one: softhsm2_one.conf
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'

softhsm2_one.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_one" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_two: softhsm2_two.conf
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0002.pem --login  --label 'SSSD test cert 0002' --id '5405842D56CF31F0BB025A695C5F3E907051C5B9'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0002.pem --login  --label 'SSSD test cert 0002' --id '5405842D56CF31F0BB025A695C5F3E907051C5B9'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'

softhsm2_two.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_two" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

CLEANFILES = \
    index.txt  index.txt.attr \
    index.txt.attr.old  index.txt.old \
    serial  serial.old  \
    SSSD_test_CA.pem $(pwdfile) \
    $(certs) $(certs_h) $(pubkeys) $(pubkeys_h) $(pkcs12) \
    softhsm2_*.conf \
    $(NULL)

clean-local:
	rm -rf newcerts
	rm -rf p11_nssdb
	rm -rf p11_nssdb_2certs
	rm -rf softhsm*

serial: clean
	touch index.txt
	touch index.txt.attr
	mkdir newcerts
	echo -n 01 > serial
