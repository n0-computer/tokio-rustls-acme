#!/bin/sh
# Writes alternate-chains.pem, a private PKI with two chains for one leaf, like Let's Encrypt's.
#
# The PEM blocks, in order:
#   0. leaf key (P-256, PKCS#8)
#   1. leaf, CN=test.example.com, issued by CN=intermediate (ECDSA SHA-384)
#   2. CN=intermediate (P-384), issued by CN=ec (ECDSA SHA-384)
#   3. CN=ec (P-384), cross-signed by CN=rsa (RSA PKCS#1 SHA-256)
#   4. CN=ec, self-signed root
#   5. CN=rsa, self-signed root (RSA 2048)
#   6. CN=intermediate, issued by CN=rsa with RSA-PSS SHA-384
#   7. CN=intermediate, issued by CN=rsa (RSA PKCS#1 SHA-256)
#   8. CN=intermediate, issued by CN=ec, expired in 2001
#   9. CN=intermediate, issued by CN=ec, not a CA
#  10. CN=intermediate, issued by CN=ec, without keyCertSign
#
# The ECDSA keys and signatures are like those of Let's Encrypt's current hierarchy.
#
# Two hierarchies use these. With the ECDSA root cross-signed by the RSA root, like ISRG Root X2
# by ISRG Root X1, the default chain [1, 2, 3] verifies to the RSA root and the alternate [1, 2]
# to the ECDSA root. With the intermediate's key signed by each root, like Let's Encrypt's E5 to
# E9 intermediates, the default chain is [1, 7] and the alternate [1, 2].
#
# Run it from any directory with OpenSSL 3.4 or later, which has -not_before and -not_after. The
# certificates are valid from 2020 until 2090.
set -eu
out="$(cd "$(dirname "$0")" && pwd)/alternate-chains.pem"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

end=20900101000000Z
start=20200101000000Z
ca_ext="basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid"
leaf_ext="basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:test.example.com
authorityKeyIdentifier=keyid"
printf '%s\n' "$ca_ext" > ca.ext
printf '%s\n' "$leaf_ext" > leaf.ext

ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$2" -out "$1"; }
ec_key ec.key P-384
ec_key intermediate.key P-384
ec_key leaf.key P-256
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key

# Self-signed roots.
for name in ec rsa; do
    openssl req -new -key $name.key -subj "/CN=$name" -out $name.csr
    openssl x509 -req -in $name.csr -signkey $name.key -not_before $start -not_after $end \
        -set_serial 1 -extfile ca.ext -sha384 -out $name.crt
done
# CN=ec cross-signed by CN=rsa.
openssl x509 -req -in ec.csr -CA rsa.crt -CAkey rsa.key -not_before $start -not_after $end \
    -set_serial 2 -extfile ca.ext -out ec-by-rsa.crt
# CN=intermediate, by CN=ec, and by CN=rsa with RSA-PSS SHA-384 and with RSA PKCS#1.
openssl req -new -key intermediate.key -subj /CN=intermediate -out intermediate.csr
openssl x509 -req -in intermediate.csr -CA ec.crt -CAkey ec.key -not_before $start \
    -not_after $end -set_serial 3 -extfile ca.ext -sha384 -out intermediate.crt
openssl x509 -req -in intermediate.csr -CA rsa.crt -CAkey rsa.key -not_before $start \
    -not_after $end -set_serial 4 -extfile ca.ext -sha384 -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha384 -out intermediate-pss.crt
openssl x509 -req -in intermediate.csr -CA rsa.crt -CAkey rsa.key -not_before $start \
    -not_after $end -set_serial 6 -extfile ca.ext -out intermediate-rsa.crt
# The leaf.
openssl req -new -key leaf.key -subj /CN=test.example.com -out leaf.csr
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key \
    -not_before $start -not_after $end -set_serial 5 -extfile leaf.ext -sha384 -out leaf.crt
# CN=intermediate in certificates that may not issue others.
printf 'basicConstraints=critical,CA:FALSE\n' > not-ca.ext
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n' > no-sign.ext
openssl x509 -req -in intermediate.csr -CA ec.crt -CAkey ec.key -not_before 20000101000000Z \
    -not_after 20010101000000Z -set_serial 7 -extfile ca.ext -sha384 -out intermediate-expired.crt
openssl x509 -req -in intermediate.csr -CA ec.crt -CAkey ec.key -not_before $start \
    -not_after $end -set_serial 8 -extfile not-ca.ext -sha384 -out intermediate-not-ca.crt
openssl x509 -req -in intermediate.csr -CA ec.crt -CAkey ec.key -not_before $start \
    -not_after $end -set_serial 9 -extfile no-sign.ext -sha384 -out intermediate-no-sign.crt

openssl pkcs8 -topk8 -nocrypt -in leaf.key > "$out"
cat leaf.crt intermediate.crt ec-by-rsa.crt ec.crt rsa.crt intermediate-pss.crt \
    intermediate-rsa.crt intermediate-expired.crt intermediate-not-ca.crt \
    intermediate-no-sign.crt >> "$out"
