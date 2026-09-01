#!/bin/sh
#
# Vendored from sipgate/li-simulator-x1x2x3.
#
# Copyright (c) sipgate GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Mutual-TLS material for the ETSI X1 interop test.
#
# Vendored from sipgate/li-simulator-x1x2x3 (MIT), whose simulator consumes the
# same shared volume and expects exactly this layout:
#
#   /mutual-tls-stores/ca-certs/<role>-ca.crt   the role's CA
#   /mutual-tls-stores/certs/<role>.crt         the role's certificate
#   /mutual-tls-stores/keys/<role>.key          its key
#
# Two roles are generated, each with its own CA, which is what makes the test
# mutual rather than one-sided:
#
#   simulator        the ADMF — siphon trusts its CA for client certificates,
#                    and binds `admfIdentifier` to its CN.
#   network-element  siphon — the simulator trusts its CA for the server
#                    certificate.
#
# Changed from the original only in using POSIX `[ ]` rather than bash `[[ ]]`,
# because this runs under the alpine shell.

set -eu

if [ -z "${ROLE:-}" ]; then
  echo "variable ROLE not set!"
  exit 1
fi

if [ -z "${COMMON_NAME:-}" ]; then
  echo "variable COMMON_NAME not set!"
  exit 1
fi

BASE_OUTPUT_PATH="/mutual-tls-stores"

if [ -f "${BASE_OUTPUT_PATH}/${ROLE}_is_ready" ]; then
  echo "${ROLE} already initialized"
  exit 0
fi

mkdir -p "${BASE_OUTPUT_PATH}/ca-certs" "${BASE_OUTPUT_PATH}/certs" "${BASE_OUTPUT_PATH}/keys"

echo "Generating ${ROLE} CA key and crt"
openssl ecparam -name prime256v1 -genkey -noout -out "/tmp/${ROLE}-ca.key"
openssl req -new -x509 -sha256 \
  -key "/tmp/${ROLE}-ca.key" \
  -out "${BASE_OUTPUT_PATH}/ca-certs/${ROLE}-ca.crt" \
  -config /init-mtls/ca-cert.conf

echo "Generating ${ROLE} key and crt (signed by that CA)"
openssl ecparam -name prime256v1 -genkey -noout -out "${BASE_OUTPUT_PATH}/keys/${ROLE}.key"
openssl req -new -sha256 \
  -key "${BASE_OUTPUT_PATH}/keys/${ROLE}.key" \
  -out /tmp/self.csr \
  -subj "/CN=${COMMON_NAME}/O=SIPhon LI interop test/C=DE"
openssl x509 -req -in /tmp/self.csr \
  -CA "${BASE_OUTPUT_PATH}/ca-certs/${ROLE}-ca.crt" \
  -CAkey "/tmp/${ROLE}-ca.key" \
  -CAcreateserial \
  -out "${BASE_OUTPUT_PATH}/certs/${ROLE}.crt" \
  -days 3650 -sha256 \
  -extfile /init-mtls/cert.conf -extensions v3_ca

# siphon reads the key as PEM through rustls-pki-types, which wants PKCS#8
# rather than the SEC1 "EC PRIVATE KEY" block `openssl ecparam` emits.
openssl pkcs8 -topk8 -nocrypt \
  -in "${BASE_OUTPUT_PATH}/keys/${ROLE}.key" \
  -out "${BASE_OUTPUT_PATH}/keys/${ROLE}.pk8.key"

chmod -R a+r "${BASE_OUTPUT_PATH}"
echo "done"

touch "${BASE_OUTPUT_PATH}/${ROLE}_is_ready"
