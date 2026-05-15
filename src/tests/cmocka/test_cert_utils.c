/*
    SSSD

    Certificates - Utilities tests

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "config.h"

#include <popt.h>
#include <tevent.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

#include "util/cert.h"
#include "tests/cmocka/common_mock.h"
#include "util/crypto/sss_crypto.h"
#include "responder/ssh/ssh_private.h"

#ifdef HAVE_TEST_CA
#include "tests/test_CA/SSSD_test_cert_pubsshkey_0001.h"
#include "tests/test_CA/SSSD_test_cert_x509_0001.h"
#include "tests/test_CA/SSSD_test_cert_pubsshkey_0002.h"
#include "tests/test_CA/SSSD_test_cert_x509_0002.h"
#include "tests/test_CA/SSSD_test_cert_pubsshkey_0007.h"
#include "tests/test_CA/SSSD_test_cert_x509_0007.h"
#include "tests/test_ECC_CA/SSSD_test_ECC_cert_pubsshkey_0001.h"
#include "tests/test_ECC_CA/SSSD_test_ECC_cert_x509_0001.h"
#else
#define SSSD_TEST_CERT_0001 ""
#define SSSD_TEST_CERT_SSH_KEY_0001 ""
#define SSSD_TEST_CERT_0002 ""
#define SSSD_TEST_CERT_SSH_KEY_0002 ""
#define SSSD_TEST_CERT_0007 ""
#define SSSD_TEST_CERT_SSH_KEY_0007 ""
#define SSSD_TEST_ECC_CERT_0001 ""
#define SSSD_TEST_ECC_CERT_SSH_KEY_0001 ""
#endif

/* When run under valgrind with --trace-children=yes we have to increase the
 * timeout not because p11_child needs much more time under valgrind but
 * because of the way valgrind handles the children. */
#define P11_CHILD_TIMEOUT 80

/* TODO: create a certificate for this test */
const uint8_t test_cert_der[] = {
0x30, 0x82, 0x04, 0x09, 0x30, 0x82, 0x02, 0xf1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x09,
0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
0x34, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x49, 0x50, 0x41, 0x2e,
0x44, 0x45, 0x56, 0x45, 0x4c, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15,
0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68,
0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x34, 0x32, 0x38, 0x31,
0x30, 0x32, 0x31, 0x31, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x34, 0x32, 0x38, 0x31, 0x30,
0x32, 0x31, 0x31, 0x31, 0x5a, 0x30, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a,
0x0c, 0x09, 0x49, 0x50, 0x41, 0x2e, 0x44, 0x45, 0x56, 0x45, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06,
0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x69, 0x70, 0x61, 0x2d, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x2e,
0x69, 0x70, 0x61, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,
0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb2, 0x32, 0x92, 0xab, 0x47, 0xb8,
0x0c, 0x13, 0x54, 0x4a, 0x1f, 0x1e, 0x29, 0x06, 0xff, 0xd0, 0x50, 0xcb, 0xf7, 0x5f, 0x79, 0x91,
0x65, 0xb1, 0x39, 0x01, 0x83, 0x6a, 0xad, 0x9e, 0x77, 0x3b, 0xf3, 0x0d, 0xd7, 0xb9, 0xf6, 0xdc,
0x9e, 0x4a, 0x49, 0xa7, 0xd0, 0x66, 0x72, 0xcc, 0xbf, 0x77, 0xd6, 0xde, 0xa9, 0xfe, 0x67, 0x96,
0xcc, 0x49, 0xf1, 0x37, 0x23, 0x2e, 0xc4, 0x50, 0xf4, 0xeb, 0xba, 0x62, 0xd4, 0x23, 0x4d, 0xf3,
0x37, 0x38, 0x82, 0xee, 0x3b, 0x3f, 0x2c, 0xd0, 0x80, 0x9b, 0x17, 0xaa, 0x9b, 0xeb, 0xa6, 0xdd,
0xf6, 0x15, 0xff, 0x06, 0xb2, 0xce, 0xff, 0xdf, 0x8a, 0x9e, 0x95, 0x85, 0x49, 0x1f, 0x84, 0xfd,
0x81, 0x26, 0xce, 0x06, 0x32, 0x0d, 0x36, 0xca, 0x7c, 0x15, 0x81, 0x68, 0x6b, 0x8f, 0x3e, 0xb3,
0xa2, 0xfc, 0xae, 0xaf, 0xc2, 0x44, 0x58, 0x15, 0x95, 0x40, 0xfc, 0x56, 0x19, 0x91, 0x80, 0xed,
0x42, 0x11, 0x66, 0x04, 0xef, 0x3c, 0xe0, 0x76, 0x33, 0x4b, 0x83, 0xfa, 0x7e, 0xb4, 0x47, 0xdc,
0xfb, 0xed, 0x46, 0xa5, 0x8d, 0x0a, 0x66, 0x87, 0xa5, 0xef, 0x7b, 0x74, 0x62, 0xac, 0xbe, 0x73,
0x36, 0xc9, 0xb4, 0xfe, 0x20, 0xc4, 0x81, 0xf3, 0xfe, 0x78, 0x19, 0xa8, 0xd0, 0xaf, 0x7f, 0x81,
0x72, 0x24, 0x61, 0xd9, 0x76, 0x93, 0xe3, 0x0b, 0xd2, 0x4f, 0x19, 0x17, 0x33, 0x57, 0xd4, 0x82,
0xb0, 0xf1, 0xa8, 0x03, 0xf6, 0x01, 0x99, 0xa9, 0xb8, 0x8c, 0x83, 0xc9, 0xba, 0x19, 0x87, 0xea,
0xd6, 0x3b, 0x06, 0xeb, 0x4c, 0xf7, 0xf1, 0xe5, 0x28, 0xa9, 0x10, 0xb6, 0x46, 0xde, 0xe1, 0xe1,
0x3f, 0xc1, 0xcc, 0x72, 0xbe, 0x2a, 0x43, 0xc6, 0xf6, 0xd0, 0xb5, 0xa0, 0xc4, 0x24, 0x6e, 0x4f,
0xbd, 0xec, 0x22, 0x8a, 0x07, 0x11, 0x3d, 0xf9, 0xd3, 0x15, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
0x82, 0x01, 0x26, 0x30, 0x82, 0x01, 0x22, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
0x30, 0x16, 0x80, 0x14, 0xf2, 0x9d, 0x42, 0x4e, 0x0f, 0xc4, 0x48, 0x25, 0x58, 0x2f, 0x1c, 0xce,
0x0f, 0xa1, 0x3f, 0x22, 0xc8, 0x55, 0xc8, 0x91, 0x30, 0x3b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x07, 0x01, 0x01, 0x04, 0x2f, 0x30, 0x2d, 0x30, 0x2b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x07, 0x30, 0x01, 0x86, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x69, 0x70, 0x61,
0x2d, 0x63, 0x61, 0x2e, 0x69, 0x70, 0x61, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x2f, 0x63, 0x61,
0x2f, 0x6f, 0x63, 0x73, 0x70, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
0x04, 0x03, 0x02, 0x04, 0xf0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14,
0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x07, 0x03, 0x02, 0x30, 0x74, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x6d, 0x30, 0x6b, 0x30,
0x69, 0xa0, 0x31, 0xa0, 0x2f, 0x86, 0x2d, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x69, 0x70,
0x61, 0x2d, 0x63, 0x61, 0x2e, 0x69, 0x70, 0x61, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x2f, 0x69,
0x70, 0x61, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x43, 0x52, 0x4c,
0x2e, 0x62, 0x69, 0x6e, 0xa2, 0x34, 0xa4, 0x32, 0x30, 0x30, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03,
0x55, 0x04, 0x0a, 0x0c, 0x05, 0x69, 0x70, 0x61, 0x63, 0x61, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03,
0x55, 0x04, 0x03, 0x0c, 0x15, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
0x0e, 0x04, 0x16, 0x04, 0x14, 0x2d, 0x2b, 0x3f, 0xcb, 0xf5, 0xb2, 0xff, 0x32, 0x2c, 0xa8, 0xc2,
0x1c, 0xdd, 0xbd, 0x8c, 0x80, 0x1e, 0xdd, 0x31, 0x82, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x9a, 0x47, 0x2e,
0x50, 0xa7, 0x4d, 0x1d, 0x53, 0x0f, 0xc9, 0x71, 0x42, 0x0c, 0xe5, 0xda, 0x7d, 0x49, 0x64, 0xe7,
0xab, 0xc8, 0xdf, 0xdf, 0x02, 0xc1, 0x87, 0xd1, 0x5b, 0xde, 0xda, 0x6f, 0x2b, 0xe4, 0xf0, 0xbe,
0xba, 0x09, 0xdf, 0x02, 0x85, 0x0b, 0x8a, 0xe6, 0x9b, 0x06, 0x7d, 0x69, 0x38, 0x6c, 0x72, 0xff,
0x4c, 0x7b, 0x2a, 0x0d, 0x3f, 0x23, 0x2f, 0x16, 0x46, 0xff, 0x05, 0x93, 0xb0, 0xea, 0x24, 0x28,
0xd7, 0x12, 0xa1, 0x57, 0xb8, 0x59, 0x19, 0x25, 0xf3, 0x43, 0x0a, 0xd3, 0xfd, 0x0f, 0x37, 0x8d,
0xb8, 0xca, 0x15, 0xe7, 0x48, 0x8a, 0xa0, 0xc7, 0xc7, 0x4b, 0x7f, 0x01, 0x3c, 0x58, 0xd7, 0x37,
0xe5, 0xff, 0x7d, 0x2b, 0x01, 0xac, 0x0d, 0x9f, 0x51, 0x6a, 0xe5, 0x40, 0x24, 0xe6, 0x5e, 0x55,
0x0d, 0xf7, 0xb8, 0x2f, 0x42, 0xac, 0x6d, 0xe5, 0x29, 0x6b, 0xc6, 0x0b, 0xa4, 0xbf, 0x19, 0xbd,
0x39, 0x27, 0xee, 0xfe, 0xc5, 0xb3, 0xdb, 0x62, 0xd4, 0xbe, 0xd2, 0x47, 0xba, 0x96, 0x30, 0x5a,
0xfd, 0x62, 0x00, 0xb8, 0x27, 0x5d, 0x2f, 0x3a, 0x94, 0x0b, 0x95, 0x35, 0x85, 0x40, 0x2c, 0xbc,
0x67, 0xdf, 0x8a, 0xf9, 0xf1, 0x7b, 0x19, 0x96, 0x3e, 0x42, 0x48, 0x13, 0x23, 0x04, 0x95, 0xa9,
0x6b, 0x11, 0x33, 0x81, 0x47, 0x5a, 0x83, 0x72, 0xf6, 0x20, 0xfa, 0x8e, 0x41, 0x7b, 0x8f, 0x77,
0x47, 0x7c, 0xc7, 0x5d, 0x46, 0xf4, 0x4f, 0xfd, 0x81, 0x0a, 0xae, 0x39, 0x27, 0xb6, 0x6a, 0x26,
0x63, 0xb1, 0xd3, 0xbf, 0x55, 0x83, 0x82, 0x9b, 0x36, 0x6c, 0x33, 0x64, 0x0f, 0x50, 0xc0, 0x55,
0x94, 0x13, 0xc3, 0x85, 0xf4, 0xd5, 0x71, 0x65, 0xd0, 0xc0, 0xdd, 0xfc, 0xe6, 0xec, 0x9c, 0x5b,
0xf0, 0x11, 0xb5, 0x2c, 0xf3, 0x48, 0xc1, 0x36, 0x8c, 0xa2, 0x96, 0x48, 0x84};

#define TEST_CERT_PEM "-----BEGIN CERTIFICATE-----\n" \
"MIIECTCCAvGgAwIBAgIBCTANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQKDAlJUEEu\n" \
"REVWRUwxHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNTA0Mjgx\n" \
"MDIxMTFaFw0xNzA0MjgxMDIxMTFaMDIxEjAQBgNVBAoMCUlQQS5ERVZFTDEcMBoG\n" \
"A1UEAwwTaXBhLWRldmVsLmlwYS5kZXZlbDCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" \
"ADCCAQoCggEBALIykqtHuAwTVEofHikG/9BQy/dfeZFlsTkBg2qtnnc78w3Xufbc\n" \
"nkpJp9Bmcsy/d9beqf5nlsxJ8TcjLsRQ9Ou6YtQjTfM3OILuOz8s0ICbF6qb66bd\n" \
"9hX/BrLO/9+KnpWFSR+E/YEmzgYyDTbKfBWBaGuPPrOi/K6vwkRYFZVA/FYZkYDt\n" \
"QhFmBO884HYzS4P6frRH3PvtRqWNCmaHpe97dGKsvnM2ybT+IMSB8/54GajQr3+B\n" \
"ciRh2XaT4wvSTxkXM1fUgrDxqAP2AZmpuIyDyboZh+rWOwbrTPfx5SipELZG3uHh\n" \
"P8HMcr4qQ8b20LWgxCRuT73sIooHET350xUCAwEAAaOCASYwggEiMB8GA1UdIwQY\n" \
"MBaAFPKdQk4PxEglWC8czg+hPyLIVciRMDsGCCsGAQUFBwEBBC8wLTArBggrBgEF\n" \
"BQcwAYYfaHR0cDovL2lwYS1jYS5pcGEuZGV2ZWwvY2Evb2NzcDAOBgNVHQ8BAf8E\n" \
"BAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHQGA1UdHwRtMGsw\n" \
"aaAxoC+GLWh0dHA6Ly9pcGEtY2EuaXBhLmRldmVsL2lwYS9jcmwvTWFzdGVyQ1JM\n" \
"LmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRl\n" \
"IEF1dGhvcml0eTAdBgNVHQ4EFgQULSs/y/Wy/zIsqMIc3b2MgB7dMYIwDQYJKoZI\n" \
"hvcNAQELBQADggEBAJpHLlCnTR1TD8lxQgzl2n1JZOeryN/fAsGH0Vve2m8r5PC+\n" \
"ugnfAoULiuabBn1pOGxy/0x7Kg0/Iy8WRv8Fk7DqJCjXEqFXuFkZJfNDCtP9DzeN\n" \
"uMoV50iKoMfHS38BPFjXN+X/fSsBrA2fUWrlQCTmXlUN97gvQqxt5Slrxgukvxm9\n" \
"OSfu/sWz22LUvtJHupYwWv1iALgnXS86lAuVNYVALLxn34r58XsZlj5CSBMjBJWp\n" \
"axEzgUdag3L2IPqOQXuPd0d8x11G9E/9gQquOSe2aiZjsdO/VYOCmzZsM2QPUMBV\n" \
"lBPDhfTVcWXQwN385uycW/ARtSzzSME2jKKWSIQ=\n" \
"-----END CERTIFICATE-----\n"

#define TEST_CERT_PEM_WITH_METADATA "Bag Attributes\n" \
"    friendlyName: ipa-devel\n" \
"    localKeyID: 8E 0D 04 1F BC 13 73 54 00 8F 65 57 D7 A8 AF 34 0C 18 B3 99\n" \
"subject= /O=IPA.DEVEL/CN=ipa-devel.ipa.devel\n" \
"issuer= /O=IPA.DEVEL/CN=Certificate Authority\n" \
TEST_CERT_PEM

#define TEST_CERT_DERB64 \
"MIIECTCCAvGgAwIBAgIBCTANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQKDAlJUEEu" \
"REVWRUwxHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNTA0Mjgx" \
"MDIxMTFaFw0xNzA0MjgxMDIxMTFaMDIxEjAQBgNVBAoMCUlQQS5ERVZFTDEcMBoG" \
"A1UEAwwTaXBhLWRldmVsLmlwYS5kZXZlbDCCASIwDQYJKoZIhvcNAQEBBQADggEP" \
"ADCCAQoCggEBALIykqtHuAwTVEofHikG/9BQy/dfeZFlsTkBg2qtnnc78w3Xufbc" \
"nkpJp9Bmcsy/d9beqf5nlsxJ8TcjLsRQ9Ou6YtQjTfM3OILuOz8s0ICbF6qb66bd" \
"9hX/BrLO/9+KnpWFSR+E/YEmzgYyDTbKfBWBaGuPPrOi/K6vwkRYFZVA/FYZkYDt" \
"QhFmBO884HYzS4P6frRH3PvtRqWNCmaHpe97dGKsvnM2ybT+IMSB8/54GajQr3+B" \
"ciRh2XaT4wvSTxkXM1fUgrDxqAP2AZmpuIyDyboZh+rWOwbrTPfx5SipELZG3uHh" \
"P8HMcr4qQ8b20LWgxCRuT73sIooHET350xUCAwEAAaOCASYwggEiMB8GA1UdIwQY" \
"MBaAFPKdQk4PxEglWC8czg+hPyLIVciRMDsGCCsGAQUFBwEBBC8wLTArBggrBgEF" \
"BQcwAYYfaHR0cDovL2lwYS1jYS5pcGEuZGV2ZWwvY2Evb2NzcDAOBgNVHQ8BAf8E" \
"BAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHQGA1UdHwRtMGsw" \
"aaAxoC+GLWh0dHA6Ly9pcGEtY2EuaXBhLmRldmVsL2lwYS9jcmwvTWFzdGVyQ1JM" \
"LmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRl" \
"IEF1dGhvcml0eTAdBgNVHQ4EFgQULSs/y/Wy/zIsqMIc3b2MgB7dMYIwDQYJKoZI" \
"hvcNAQELBQADggEBAJpHLlCnTR1TD8lxQgzl2n1JZOeryN/fAsGH0Vve2m8r5PC+" \
"ugnfAoULiuabBn1pOGxy/0x7Kg0/Iy8WRv8Fk7DqJCjXEqFXuFkZJfNDCtP9DzeN" \
"uMoV50iKoMfHS38BPFjXN+X/fSsBrA2fUWrlQCTmXlUN97gvQqxt5Slrxgukvxm9" \
"OSfu/sWz22LUvtJHupYwWv1iALgnXS86lAuVNYVALLxn34r58XsZlj5CSBMjBJWp" \
"axEzgUdag3L2IPqOQXuPd0d8x11G9E/9gQquOSe2aiZjsdO/VYOCmzZsM2QPUMBV" \
"lBPDhfTVcWXQwN385uycW/ARtSzzSME2jKKWSIQ="

struct test_state {
    void *dummy;
    bool done;
    struct sss_certmap_ctx *sss_certmap_ctx;
};

static int setup(void **state)
{
    struct test_state *ts = NULL;

    assert_true(leak_check_setup());

    ts = talloc(global_talloc_context, struct test_state);
    assert_non_null(ts);

    check_leaks_push(ts);
    *state = (void *)ts;
    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    assert_non_null(ts);

    assert_true(check_leaks_pop(ts));
    talloc_free(ts);
    assert_true(leak_check_teardown());
    return 0;
}

void test_sss_cert_der_to_pem(void **state)
{
    int ret;
    char *pem_str;
    size_t pem_size;
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);

    ret = sss_cert_der_to_pem(NULL, NULL, 0, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_cert_der_to_pem(ts, test_cert_der, sizeof(test_cert_der),
                              &pem_str, &pem_size);
    assert_int_equal(ret, EOK);
    assert_int_equal(sizeof(TEST_CERT_PEM) - 1, pem_size);
    assert_string_equal(pem_str, TEST_CERT_PEM);

    talloc_free(pem_str);
}

void test_sss_cert_pem_to_der(void **state)
{
    int ret;
    uint8_t *der;
    size_t der_size;
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);

    ret = sss_cert_pem_to_der(NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_cert_pem_to_der(ts, TEST_CERT_PEM, &der, &der_size);
    assert_int_equal(ret, EOK);
    assert_int_equal(sizeof(test_cert_der), der_size);
    assert_memory_equal(der, test_cert_der, der_size);

    talloc_free(der);

    /* https://github.com/SSSD/sssd/issues/4384
       https://tools.ietf.org/html/rfc7468#section-2 */
    ret = sss_cert_pem_to_der(ts, TEST_CERT_PEM_WITH_METADATA, &der, &der_size);
    assert_int_equal(ret, EOK);
    assert_int_equal(sizeof(test_cert_der), der_size);
    assert_memory_equal(der, test_cert_der, der_size);

    talloc_free(der);
}

void test_sss_cert_derb64_to_pem(void **state)
{
    int ret;
    char *pem_str;
    size_t pem_size;
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);

    ret = sss_cert_derb64_to_pem(NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_cert_derb64_to_pem(ts, TEST_CERT_DERB64, &pem_str, &pem_size);
    assert_int_equal(ret, EOK);
    assert_int_equal(sizeof(TEST_CERT_PEM) - 1, pem_size);
    assert_string_equal(pem_str, TEST_CERT_PEM);

    talloc_free(pem_str);
}

void test_sss_cert_pem_to_derb64(void **state)
{
    int ret;
    char *derb64;
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);

    ret = sss_cert_pem_to_derb64(NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_cert_pem_to_derb64(ts, TEST_CERT_PEM, &derb64);
    assert_int_equal(ret, EOK);
    assert_string_equal(derb64, TEST_CERT_DERB64);

    talloc_free(derb64);
}

void test_bin_to_ldap_filter_value(void **state)
{
    int ret;
    size_t c;
    char *str;
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);

    struct test_data {
        uint8_t blob[5];
        const char *str;
    }  test_data[] = {
        {{0x01, 0x02, 0x03, 0x04, 0x05}, "\\01\\02\\03\\04\\05"},
        {{0x00, 0x00, 0x00, 0x00, 0x00}, "\\00\\00\\00\\00\\00"},
        {{0xff, 0xff, 0xff, 0xff, 0xff}, "\\ff\\ff\\ff\\ff\\ff"},
        {{0xca, 0xfe, 0xc0, 0xff, 0xee}, "\\ca\\fe\\c0\\ff\\ee"},
        {{0}, NULL}
    };

    ret = bin_to_ldap_filter_value(ts, NULL, 0, NULL);
    assert_int_equal(ret, EINVAL);

    for (c = 0; test_data[c].str != NULL; c++) {
        ret = bin_to_ldap_filter_value(ts, test_data[c].blob, 5, &str);
        assert_int_equal(ret, EOK);
        assert_string_equal(str, test_data[c].str);

        talloc_free(str);
    }

}

void test_sss_cert_derb64_to_ldap_filter(void **state)
{
    int ret;
    char *filter;

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);

    ret = sss_cert_derb64_to_ldap_filter(ts, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_cert_derb64_to_ldap_filter(ts, "AAECAwQFBgcICQ==", "attrName",
                                         NULL, NULL, &filter);
    assert_int_equal(ret, EOK);
    assert_string_equal(filter,
                        "(attrName=\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09)");

    talloc_free(filter);
}

void test_pss_cert_to_ssh_key_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_int_equal(valid_keys, 1);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0007, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);

    talloc_free(exp_key);
    talloc_free(keys);
}

void test_pss_cert_to_ssh_key_send(void **state)
{
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[1];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    val[0].data = sss_base64_decode(ts, SSSD_TEST_CERT_0007, &val[0].length);
    assert_non_null(val[0].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                            ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA.pem",
                            NULL, 1, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_pss_cert_to_ssh_key_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(ev);
}

void test_cert_to_ssh_key_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_int_equal(valid_keys, 1);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0001, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);

    talloc_free(exp_key);
    talloc_free(keys);
}

void test_cert_to_ssh_key_send(void **state)
{
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[1];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    val[0].data = sss_base64_decode(ts, SSSD_TEST_CERT_0001, &val[0].length);
    assert_non_null(val[0].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                            ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA.pem",
                            NULL, 1, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_cert_to_ssh_key_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(ev);
}

void test_cert_to_ssh_2keys_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_non_null(keys[1].data);
    assert_int_equal(valid_keys, 2);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0001, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);
    talloc_free(exp_key);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0002, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[1].length, exp_key_size);
    assert_memory_equal(keys[1].data, exp_key, exp_key_size);
    talloc_free(exp_key);

    talloc_free(keys);
}

void test_cert_to_ssh_2keys_send(void **state)
{
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[2];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    val[0].data = sss_base64_decode(ts, SSSD_TEST_CERT_0001,
                                          &val[0].length);
    assert_non_null(val[0].data);

    val[1].data = sss_base64_decode(ts, SSSD_TEST_CERT_0002,
                                          &val[1].length);
    assert_non_null(val[1].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                            ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA.pem",
                            NULL, 2, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_cert_to_ssh_2keys_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(val[1].data);
    talloc_free(ev);
}

void test_cert_to_ssh_2keys_invalid_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_null(keys[1].data);
    assert_int_equal(keys[1].length, 0);
    assert_non_null(keys[2].data);
    assert_int_equal(valid_keys, 2);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0001, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);
    talloc_free(exp_key);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0002, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[2].length, exp_key_size);
    assert_memory_equal(keys[2].data, exp_key, exp_key_size);
    talloc_free(exp_key);

    talloc_free(keys);
}

void test_cert_to_ssh_2keys_invalid_send(void **state)
{
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[3];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    val[0].data = sss_base64_decode(ts, SSSD_TEST_CERT_0001,
                                          &val[0].length);
    assert_non_null(val[0].data);

    val[1].data = sss_base64_decode(ts, SSSD_TEST_CERT_0002,
                                          &val[1].length);
    assert_non_null(val[1].data);
    /* flip last bit to make the certificate invalid */
    val[1].data[val[1].length - 1] ^= 1 << 0;

    val[2].data = sss_base64_decode(ts, SSSD_TEST_CERT_0002,
                                          &val[2].length);
    assert_non_null(val[2].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                            ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA.pem",
                            NULL, 3, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_cert_to_ssh_2keys_invalid_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(val[1].data);
    talloc_free(val[2].data);
    talloc_free(ev);
}

void test_ec_cert_to_ssh_key_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_int_equal(valid_keys, 1);

    exp_key = sss_base64_decode(ts, SSSD_TEST_ECC_CERT_SSH_KEY_0001,
                                &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);

    talloc_free(exp_key);
    talloc_free(keys);
}

void test_ec_cert_to_ssh_key_send(void **state)
{
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[1];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    val[0].data = sss_base64_decode(ts, SSSD_TEST_ECC_CERT_0001,
                                    &val[0].length);
    assert_non_null(val[0].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                    ABS_BUILD_DIR "/src/tests/test_ECC_CA/SSSD_test_ECC_CA.pem",
                    NULL, 1, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_ec_cert_to_ssh_key_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(ev);
}

void test_cert_to_ssh_2keys_with_certmap_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_int_equal(valid_keys, 1);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0001, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);
    talloc_free(exp_key);

    talloc_free(keys);
    sss_certmap_free_ctx(ts->sss_certmap_ctx);
}

void test_cert_to_ssh_2keys_with_certmap_send(void **state)
{
    int ret;
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[2];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    ret = sss_certmap_init(ts, NULL, NULL, &ts->sss_certmap_ctx);
    assert_int_equal(ret, EOK);

    ret = sss_certmap_add_rule(ts->sss_certmap_ctx, -1,
                               "<SUBJECT>CN=SSSD test cert 0001,.*", NULL,
                               NULL);
    assert_int_equal(ret, EOK);

    val[0].data = sss_base64_decode(ts, SSSD_TEST_CERT_0001,
                                          &val[0].length);
    assert_non_null(val[0].data);

    val[1].data = sss_base64_decode(ts, SSSD_TEST_CERT_0002,
                                          &val[1].length);
    assert_non_null(val[1].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                            ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA.pem",
                            ts->sss_certmap_ctx, 2, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_cert_to_ssh_2keys_with_certmap_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(val[1].data);
    talloc_free(ev);
}

void test_cert_to_ssh_2keys_with_certmap_2_done(struct tevent_req *req)
{
    int ret;
    struct test_state *ts = tevent_req_callback_data(req, struct test_state);
    struct ldb_val *keys;
    uint8_t *exp_key;
    size_t exp_key_size;
    size_t valid_keys;

    assert_non_null(ts);
    ts->done = true;

    ret = cert_to_ssh_key_recv(req, ts, &keys, &valid_keys);
    talloc_free(req);
    assert_int_equal(ret, 0);
    assert_non_null(keys[0].data);
    assert_int_equal(valid_keys, 1);

    exp_key = sss_base64_decode(ts, SSSD_TEST_CERT_SSH_KEY_0002, &exp_key_size);
    assert_non_null(exp_key);
    assert_int_equal(keys[0].length, exp_key_size);
    assert_memory_equal(keys[0].data, exp_key, exp_key_size);
    talloc_free(exp_key);

    talloc_free(keys);
    sss_certmap_free_ctx(ts->sss_certmap_ctx);
}

void test_cert_to_ssh_2keys_with_certmap_2_send(void **state)
{
    int ret;
    struct tevent_context *ev;
    struct tevent_req *req;
    struct ldb_val val[2];

    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    assert_non_null(ts);
    ts->done = false;

    ret = sss_certmap_init(ts, NULL, NULL, &ts->sss_certmap_ctx);
    assert_int_equal(ret, EOK);

    ret = sss_certmap_add_rule(ts->sss_certmap_ctx, -1,
                               "<SUBJECT>CN=SSSD test cert 0002,.*", NULL,
                               NULL);
    assert_int_equal(ret, EOK);

    val[0].data = sss_base64_decode(ts, SSSD_TEST_CERT_0001,
                                          &val[0].length);
    assert_non_null(val[0].data);

    val[1].data = sss_base64_decode(ts, SSSD_TEST_CERT_0002,
                                          &val[1].length);
    assert_non_null(val[1].data);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    req = cert_to_ssh_key_send(ts, ev, NULL, P11_CHILD_TIMEOUT,
                            ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA.pem",
                            ts->sss_certmap_ctx, 2, &val[0], NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_cert_to_ssh_2keys_with_certmap_2_done, ts);

    while (!ts->done) {
        tevent_loop_once(ev);
    }

    talloc_free(val[0].data);
    talloc_free(val[1].data);
    talloc_free(ev);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int ret;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sss_cert_der_to_pem,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_cert_pem_to_der,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_cert_derb64_to_pem,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_cert_pem_to_derb64,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_bin_to_ldap_filter_value,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_cert_derb64_to_ldap_filter,
                                        setup, teardown),
#ifdef HAVE_TEST_CA
        cmocka_unit_test_setup_teardown(test_cert_to_ssh_key_send,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_cert_to_ssh_2keys_send,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_cert_to_ssh_2keys_invalid_send,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_ec_cert_to_ssh_key_send,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_pss_cert_to_ssh_key_send,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_cert_to_ssh_2keys_with_certmap_send,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_cert_to_ssh_2keys_with_certmap_2_send,
                                        setup, teardown),
#endif
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    ret = cmocka_run_group_tests(tests, NULL, NULL);

    CRYPTO_cleanup_all_ex_data(); /* to make Valgrind happy */

    return ret;
}
