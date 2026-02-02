#!/usr/bin/python3
#
# SPDX-License-Identifier: 0BSD
# Part of badkeys: https://badkeys.info/

import argparse
import json
import pathlib
import urllib
import urllib.request

DEBUG = True


def _debugmsg(msg):
    if DEBUG:
        fmsg = repr(msg)[1:-1]
        print(f"DEBUG: {fmsg}")


def parsesectxt(rawdata):
    try:
        sectxt = rawdata.decode("utf-8").strip().split("\n")
    except UnicodeDecodeError:
        return None
    dat = {}
    for line in sectxt:
        if line.startswith("#") or line.strip() == "":
            # skip comments and empty lines
            continue
        try:
            k, v = line.strip().split(":", 1)
        except ValueError:
            _debugmsg(f"cannot decode line {line}")
            continue
        v = v.strip()
        # keys are case insensitive, so we lowercase them
        k = k.lower()
        if k not in dat:
            dat[k] = v
        else:
            if isinstance(dat[k], str):
                dat[k] = [dat[k]]
            dat[k].append(v)
    return dat


def getsecuritytxt(hostname):
    sectxturl = f"https://{hostname}/.well-known/security.txt"
    try:
        with urllib.request.urlopen(sectxturl) as u:
            sectxt = u.read()
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None

    return parsesectxt(sectxt)


def getreportingemails(hostname):
    emails = []
    sectxt = getsecuritytxt(hostname)
    if sectxt and "contact" in sectxt:
        contacts = sectxt["contact"]
        if isinstance(contacts, str):
            contacts = [contacts]
        for contact in contacts:
            up = urllib.parse.urlparse(contact)
            if up.scheme == "mailto":
                # fixme check query fragment params empty
                emails.append(up.path)
    if emails:
        _debugmsg("security.txt mail contact(s) found")
    else:
        _debugmsg("no security.txt mail contact, use RFC 2142 (security@[...])")
        emails = [f"security@{hostname}"]
    return emails


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hostnames", nargs="+")
    ap.add_argument("-f", "--files", action="store_true")
    args = ap.parse_args()

    if args.files:
        for fp in args.hostnames:
            rawdata = pathlib.Path(fp).read_bytes()
            sectxt = parsesectxt(rawdata)
    else:
        for hostname in args.hostnames:
            sectxt = getsecuritytxt(hostname)

    print(json.dumps(sectxt, indent=2))
