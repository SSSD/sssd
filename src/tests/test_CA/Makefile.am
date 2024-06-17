dist_noinst_DATA = \
    SSSD_test_CA.config \
    SSSD_test_CA_key.pem \
    SSSD_test_cert_0001.config \
    SSSD_test_cert_0002.config \
    SSSD_test_cert_0003.config \
    SSSD_test_cert_0004.config \
    SSSD_test_cert_0005.config \
    SSSD_test_cert_0006.config \
    SSSD_test_cert_0007.config \
    SSSD_test_cert_0008.config \
    SSSD_test_cert_0009.config \
    SSSD_test_cert_key_0001.pem \
    SSSD_test_cert_key_0002.pem \
    SSSD_test_cert_key_0003.pem \
    SSSD_test_cert_key_0004.pem \
    SSSD_test_cert_key_0005.pem \
    SSSD_test_cert_key_0007.pem \
    SSSD_test_cert_key_0008.pem \
    SSSD_test_cert_key_0009.pem \
    $(NULL)

openssl_ca_config = $(srcdir)/SSSD_test_CA.config
openssl_ca_key = $(srcdir)/SSSD_test_CA_key.pem
pwdfile = pwdfile

full_configs := $(notdir $(wildcard $(srcdir)/SSSD_test_cert_*.config))
if HAVE_FAKETIME
configs := $(full_configs)
else
configs := $(filter-out SSSD_test_cert_0008.config,$(full_configs))
endif
ids := $(subst SSSD_test_cert_,,$(basename $(configs)))
certs = $(addprefix SSSD_test_cert_x509_,$(addsuffix .pem,$(ids)))
certs_h = $(addprefix SSSD_test_cert_x509_,$(addsuffix .h,$(ids)))
pubkeys = $(addprefix SSSD_test_cert_pubsshkey_,$(addsuffix .pub,$(ids)))
pubkeys_h = $(addprefix SSSD_test_cert_pubsshkey_,$(addsuffix .h,$(ids)))
pkcs12 = $(addprefix SSSD_test_cert_pkcs12_,$(addsuffix .pem,$(ids)))


extra = softhsm2_none softhsm2_one softhsm2_two softhsm2_2tokens softhsm2_ocsp softhsm2_2certs_same_id softhsm2_pss_one softhsm2_revoked SSSD_test_cert_x509_0001.der SSSD_test_cert_x509_0007.der
if HAVE_FAKETIME
extra += softhsm2_expired
endif

# CRL files should be generated last to make sure all revoked certificates are
# included
extra += SSSD_test_CA_crl.pem
if HAVE_FAKETIME
extra += SSSD_test_CA_expired_crl.pem
endif

# If openssl is run in parallel there might be conflicts with the serial
.NOTPARALLEL:

ca_all: clean serial SSSD_test_CA.pem $(certs) $(certs_h) $(pubkeys) $(pubkeys_h) $(pkcs12) $(extra)

$(pwdfile):
	@echo "123456" > $@

SSSD_test_CA.pem: $(openssl_ca_key) $(openssl_ca_config) serial
	$(OPENSSL) req -batch -config ${openssl_ca_config} -x509 -new -nodes -key $< -sha256 -days 1024 -set_serial 0 -extensions v3_ca -out $@

# SSSD_test_cert_0006 should use the same key as SSSD_test_cert_0001
.INTERMEDIATE: SSSD_test_cert_req_0006.pem
SSSD_test_cert_req_0006.pem: $(srcdir)/SSSD_test_cert_key_0001.pem $(srcdir)/SSSD_test_cert_0006.config
	if [ $(shell grep -c req_exts $(srcdir)/SSSD_test_cert_0006.config) -eq 0 ]; then \
		$(OPENSSL) req -new -nodes -key $< -config $(srcdir)/SSSD_test_cert_0006.config -out $@ ; \
	else \
		$(OPENSSL) req -new -nodes -key $< -reqexts req_exts -config $(srcdir)/SSSD_test_cert_0006.config -out $@ ; \
	fi

# SSSD_test_cert_0007 should produce a rsassapss signed cert with nondefault settings as seen by some 3rd party CA:s
.INTERMEDIATE: SSSD_test_cert_req_0007.pem
SSSD_test_cert_req_0007.pem: $(srcdir)/SSSD_test_cert_key_0007.pem $(srcdir)/SSSD_test_cert_0007.config
	if [ $(shell grep -c req_exts $(srcdir)/SSSD_test_cert_0007.config) -eq 0 ]; then \
		$(OPENSSL) req -new -key $< -config $(srcdir)/SSSD_test_cert_0007.config  -sigopt rsa_padding_mode\:pss -sha256 -sigopt rsa_pss_saltlen\:20 -out $@ ;  \
	else \
		$(OPENSSL) req -new -key $< -reqexts req_exts -config $(srcdir)/SSSD_test_cert_0007.config  -sigopt rsa_padding_mode\:pss -sha256 -sigopt rsa_pss_saltlen\:20 -out $@ ; \
	fi

SSSD_test_cert_req_%.pem: $(srcdir)/SSSD_test_cert_key_%.pem $(srcdir)/SSSD_test_cert_%.config
	if [ $(shell grep -c req_exts $(srcdir)/SSSD_test_cert_$*.config) -eq 0 ]; then \
		$(OPENSSL) req -new -nodes -key $< -config $(srcdir)/SSSD_test_cert_$*.config -out $@ ; \
	else \
		$(OPENSSL) req -new -nodes -key $< -reqexts req_exts -config $(srcdir)/SSSD_test_cert_$*.config -out $@ ; \
	fi

SSSD_test_cert_x509_%.pem: SSSD_test_cert_req_%.pem $(openssl_ca_config) SSSD_test_CA.pem
	$(OPENSSL) ca -config ${openssl_ca_config} -batch -notext -keyfile $(openssl_ca_key) -in $< -days 200 -extensions usr_cert -out $@

SSSD_test_cert_pkcs12_0006.pem: SSSD_test_cert_x509_0006.pem $(srcdir)/SSSD_test_cert_key_0001.pem $(pwdfile)
	$(OPENSSL) pkcs12 -export -in SSSD_test_cert_x509_0006.pem -inkey $(srcdir)/SSSD_test_cert_key_0001.pem -nodes -passout file:$(pwdfile) -out $@

SSSD_test_cert_x509_0007.pem: SSSD_test_cert_req_0007.pem $(openssl_ca_config) SSSD_test_CA.pem
	$(OPENSSL) ca -config ${openssl_ca_config} -batch -notext -keyfile $(openssl_ca_key) -in $< -sigopt rsa_padding_mode\:pss  -sigopt rsa_pss_saltlen\:20 -days 200 -extensions usr_cert -out $@

.INTERMEDIATE: SSSD_test_cert_req_0008.pem
SSSD_test_cert_x509_0008.pem: SSSD_test_cert_req_0008.pem $(openssl_ca_config) SSSD_test_CA.pem
	$(FAKETIME) -f '-10y' $(OPENSSL) ca -config ${openssl_ca_config} -batch -notext -keyfile $(openssl_ca_key) -in $< -days 200 -extensions usr_cert -out $@

.INTERMEDIATE: SSSD_test_cert_req_0009.pem
SSSD_test_cert_x509_0009.pem: SSSD_test_cert_req_0009.pem $(openssl_ca_config) SSSD_test_CA.pem
	$(OPENSSL) ca -config ${openssl_ca_config} -batch -notext -keyfile $(openssl_ca_key) -in $< -days 200 -extensions usr_cert -out $@
	$(OPENSSL) ca -config ${openssl_ca_config} -batch -notext -keyfile $(openssl_ca_key) -revoke $@

SSSD_test_cert_pkcs12_%.pem: SSSD_test_cert_x509_%.pem $(srcdir)/SSSD_test_cert_key_%.pem $(pwdfile)
	$(OPENSSL) pkcs12 -export -in SSSD_test_cert_x509_$*.pem -inkey $(srcdir)/SSSD_test_cert_key_$*.pem -nodes -passout file:$(pwdfile) -out $@

SSSD_test_cert_pubkey_%.pem: SSSD_test_cert_x509_%.pem
	$(OPENSSL) x509 -in $< -pubkey -noout > $@

SSSD_test_cert_pubsshkey_%.pub: SSSD_test_cert_pubkey_%.pem
	$(SSH_KEYGEN) -i -m PKCS8 -f $< > $@

SSSD_test_cert_x509_%.h: SSSD_test_cert_x509_%.pem
	@echo "#define SSSD_TEST_CERT_$* \""$(shell cat $< |openssl x509 -outform der | base64 -w 0)"\"" > $@
	@echo "#define SSSD_TEST_CERT_SERIAL_$* \"\\x"$(shell cat $< |openssl x509 -noout -serial | cut -d= -f2)"\"" >> $@
	@echo "#define SSSD_TEST_CERT_DEC_SERIAL_$* \""$(shell echo ibase=16\; $(shell cat $< |openssl x509 -noout -serial | cut -d= -f2) | bc)"\"" >> $@

SSSD_test_cert_pubsshkey_%.h: SSSD_test_cert_pubsshkey_%.pub
	@echo "#define SSSD_TEST_CERT_SSH_KEY_$* \""$(shell cut -d' ' -f2 $<)"\"" > $@

SSSD_test_CA_expired_crl.pem:
	$(FAKETIME) -f '-7d' $(OPENSSL) ca -gencrl -out $@ -keyfile $(openssl_ca_key) -config ${openssl_ca_config} -crlhours 1

SSSD_test_CA_crl.pem: $(openssl_ca_key) SSSD_test_CA.pem
	$(OPENSSL) ca -gencrl -out $@ -keyfile $(openssl_ca_key) -config $(openssl_ca_config) -crldays 99

# The softhsm2 PKCS#11 setups are used in
# - src/tests/cmocka/test_pam_srv.c
softhsm2_none: softhsm2_none.conf
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free

softhsm2_none.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_none" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_one: softhsm2_one.conf softhsm2_mech_rsa_pkcs.conf softhsm2_mech_rsa_sha384_pkcs.conf SSSD_test_cert_x509_0001.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'

softhsm2_one.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_one" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_mech_rsa_pkcs.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_one" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@
	@echo "slots.mechanisms = CKM_RSA_PKCS" >> $@

softhsm2_mech_rsa_sha384_pkcs.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_one" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@
	@echo "slots.mechanisms = CKM_SHA384_RSA_PKCS" >> $@

#Export cert from softhsm2 via p11tool, should produce the same as openssl
SSSD_test_cert_x509_0001.der: softhsm2_one.conf
	$(eval ID_VAR = $(shell GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --info|cut -d' ' -f2|grep ^pkcs11))
	@echo  ID_VAR=$(ID_VAR) GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) '$(ID_VAR)' --export --outder --outfile $@

SSSD_test_cert_x509_0007.der: softhsm2_pss_one.conf
	$(eval ID_VAR = $(shell GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --info|cut -d' ' -f2|grep ^pkcs11))
	@echo ID_VAR=$(ID_VAR) GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) '$(ID_VAR)' --export --outder --outfile $@

softhsm2_two: softhsm2_two.conf SSSD_test_cert_x509_0002.pem SSSD_test_cert_x509_0001.pem
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

softhsm2_2tokens: softhsm2_2tokens.conf SSSD_test_cert_x509_0002.pem SSSD_test_cert_x509_0001.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17' pkcs11:token=SSSD%20Test%20Token
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0001.pem --login  --label 'SSSD test cert 0001' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17' pkcs11:token=SSSD%20Test%20Token
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token Number 2" --pin 654321 --so-pin 654321 --free
	GNUTLS_PIN=654321 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0002.pem --login  --label 'SSSD test cert 0002' --id '5405842D56CF31F0BB025A695C5F3E907051C5B9' pkcs11:token=SSSD%20Test%20Token%20Number%202
	GNUTLS_PIN=654321 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0002.pem --login  --label 'SSSD test cert 0002' --id '5405842D56CF31F0BB025A695C5F3E907051C5B9' pkcs11:token=SSSD%20Test%20Token%20Number%202

softhsm2_2tokens.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_2tokens" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_ocsp: softhsm2_ocsp.conf SSSD_test_cert_x509_0005.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0005.pem --login  --label 'SSSD test cert 0005' --id '1195833C424AB00297F582FC43FFFFAB47A64CC9'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0005.pem --login  --label 'SSSD test cert 0005' --id '1195833C424AB00297F582FC43FFFFAB47A64CC9'

softhsm2_ocsp.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_ocsp" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_2certs_same_id: softhsm2_2certs_same_id.conf SSSD_test_cert_x509_0001.pem SSSD_test_cert_x509_0006.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0006.pem --login  --label 'SSSD test cert 0006' --id '11111111'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0001.pem --login  --label 'SSSD test cert 0001' --id '11111111'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0001.pem --login  --label 'SSSD test cert 0001' --id '11111111'

softhsm2_2certs_same_id.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_2certs_same_id" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_pss_one: softhsm2_pss_one.conf SSSD_test_cert_x509_0007.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0007.pem --login  --label 'SSSD test cert 0007' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0007.pem --login  --label 'SSSD test cert 0007' --id 'C554C9F82C2A9D58B70921C143304153A8A42F17'

softhsm2_pss_one.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_pss_one" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_expired: softhsm2_expired.conf SSSD_test_cert_x509_0008.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token Expired" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0008.pem --login  --label 'SSSD test cert 0008' --id '123456'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0008.pem --login  --label 'SSSD test cert 0008' --id '123456'

softhsm2_expired.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_expired" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

softhsm2_revoked: softhsm2_revoked.conf SSSD_test_cert_x509_0009.pem
	mkdir $@
	SOFTHSM2_CONF=./$< $(SOFTHSM2_UTIL) --init-token  --label "SSSD Test Token Revoked" --pin 123456 --so-pin 123456 --free
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --no-mark-private --load-certificate=SSSD_test_cert_x509_0009.pem --login  --label 'SSSD test cert 0009' --id '123456'
	GNUTLS_PIN=123456 SOFTHSM2_CONF=./$< $(P11TOOL) --provider=$(SOFTHSM2_PATH) --write --load-privkey=$(srcdir)/SSSD_test_cert_key_0009.pem --login  --label 'SSSD test cert 0009' --id '123456'

softhsm2_revoked.conf:
	@echo "directories.tokendir = "$(abs_top_builddir)"/src/tests/test_CA/softhsm2_revoked" > $@
	@echo "objectstore.backend = file" >> $@
	@echo "slots.removable = true" >> $@

CLEANFILES = \
    index.txt  index.txt.attr \
    index.txt.attr.old  index.txt.old \
    serial  serial.old  \
    SSSD_test_CA.pem $(pwdfile) SSSD_test_CA_expired_crl.pem \
    SSSD_test_CA_crl.pem \
    $(certs) $(certs_h) $(pubkeys) $(pubkeys_h) $(pkcs12) \
    softhsm2_*.conf \
    SSSD_test_*.der \
    $(NULL)

clean-local:
	rm -rf newcerts
	rm -rf softhsm*

serial:
	touch index.txt
	touch index.txt.attr
	mkdir newcerts
	echo -n 01 > serial

SUBDIRS = intermediate_CA
