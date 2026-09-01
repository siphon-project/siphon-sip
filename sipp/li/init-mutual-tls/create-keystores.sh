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
# Java keystores for the simulator.
#
# Vendored from sipgate/li-simulator-x1x2x3 (MIT), where this exists to set up
# their Wiremock stand-in network element. We do not use Wiremock — siphon is
# the network element here — but the simulator builds this SSL context eagerly
# at startup regardless, so the files have to exist or it will not boot.
#
# siphon itself needs none of this: it reads PEM directly. This is purely to
# satisfy the peer.

set -eu

STORES=/mutual-tls-stores

echo "Cleaning up old stores..."
rm -f "${STORES}/network-element-truststore.jks" "${STORES}/network-element-keystore.p12"

echo "Importing the simulator CA..."
keytool -import -storetype jks -noprompt -trustcacerts \
  -alias simulator-ca.crt \
  -file "${STORES}/ca-certs/simulator-ca.crt" \
  -keystore "${STORES}/network-element-truststore.jks" \
  -storepass changeit

echo "Importing the simulator certificate..."
keytool -import -storetype jks -noprompt \
  -alias simulator.crt \
  -file "${STORES}/certs/simulator.crt" \
  -keystore "${STORES}/network-element-truststore.jks" \
  -storepass changeit

echo "Creating the PKCS12 keystore..."
openssl pkcs12 -export \
  -in "${STORES}/certs/network-element.crt" \
  -inkey "${STORES}/keys/network-element.key" \
  -out "${STORES}/network-element-keystore.p12" \
  -name network-element \
  -passout pass:changeit

chmod -R a+r "${STORES}"
echo "done"
