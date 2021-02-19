#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# (c) 2021 Simon Biewald
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import ssl
import time

from datetime import datetime

from ldap3 import Server, Connection, DSA, NTLM, Tls

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

TIME_CRITICAL=4*60
TIME_WARNING=60

parser = argparse.ArgumentParser()
auth = parser.add_argument_group("authentication")
auth.add_argument("--user", "-U", help="Username to login with in 'DOMAIN\\samAccountName' format.")
auth.add_argument("--pass", "-P", help="Password to username")
auth.add_argument("--ntlm", "-N", action="store_true", default=False, help="Use NTLM instead of simple bind")
parser.add_argument("--domain", "-D", required=True, help="Domain or AD server")
parser.add_argument("--ldaps", "-S", action="store_true", default=False, help="Use LDAPS instead of LDAP.")
parser.add_argument("--insecure", "-k", action="store_true", default=False, help="Do not verify LDAP certificate.")

if __name__ == "__main__":
    args = parser.parse_args()
    t = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
    if args.insecure:
        t = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
    s = Server(host=args.domain, port=636 if args.ldaps else 389, use_ssl=args.ldaps, get_info=DSA, tls=t)
    if not args.user:
        c = Connection(s)
    elif args.ntlm:
        c = Connection(s, user=args.user, password=getattr(args, 'pass'), authentication=NTLM)
    else:
        c = Connection(s, user=args.user, password=getattr(args, 'pass'))

    try:
        if not c.bind():
            print("AD CRITICAL - Bind unsuccessful")
            exit(CRITICAL)
    except Exception as e:
        print(f"AD CRITICAL - {e}")
        exit(CRITICAL)

    timediff = abs((datetime.utcnow() - datetime.strptime(s.info.raw['currentTime'][0].decode(), '%Y%m%d%H%M%S.0Z')).total_seconds())

    if timediff >= TIME_CRITICAL:
        status = CRITICAL
        text = "AD CRITICAL - Time difference > 4 minutes 30 seconds."
    elif timediff >= TIME_WARNING:
        status = WARNING
        text = "AD WARNING - Time difference > 1 minute."
    elif not s.info.raw['isSynchronized'][0] == b'TRUE':
        status = WARNING
        text = "AD WARNING - Not synchronized"
    else:
        status = OK
        text = "OK"

    print(f"{text};|", end=' ')
    print(f"'time difference'={timediff}s;{TIME_WARNING};{TIME_CRITICAL};0;null;", end=' ')
    print()

    print(repr(s.info))

    exit(status)
