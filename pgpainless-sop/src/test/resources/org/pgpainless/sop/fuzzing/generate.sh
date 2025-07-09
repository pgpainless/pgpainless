#!/bin/bash

SOP=pgpainless-cli
USERID="Alice <alice@pgpainless.org>"
KEYSDIR="testKeys"
TESTDIR="EncryptedMessageFuzzingTestInputs/decryptFuzzedMessage"

mkdir $KEYSDIR
mkdir -p $TESTDIR

echo "Hello, World!" > $TESTDIR/msg
echo -n "sw0rdf1sh" > $TESTDIR/pass

gen_profiles=$($SOP list-profiles generate-key | awk '{ sub(/:$/, "", $1); print $1 }')
enc_profiles=$($SOP list-profiles encrypt | awk '{ sub(/:$/, "", $1); print $1 }')


for p in $gen_profiles; do
    $SOP generate-key --profile=$p "$USERID" > $KEYSDIR/$p.key.asc
    $SOP extract-cert < $KEYSDIR/$p.key.asc > $KEYSDIR/$p.cert.asc
    $SOP dearmor < $KEYSDIR/$p.cert.asc > $KEYSDIR/$p.cert.pgp

    for m in $enc_profiles; do
        $SOP encrypt --profile=$m $KEYSDIR/$p.cert.asc < $TESTDIR/msg > $TESTDIR/$p.$m.pgp.asc
        $SOP dearmor < $TESTDIR/$p.$m.pgp.asc > $TESTDIR/$p.$m.pgp
    done
done

for m in $enc_profiles; do
    $SOP encrypt --profile=$m --with-password=$TESTDIR/pass < $TESTDIR/msg > $TESTDIR/password.$m.pgp.asc
    $SOP dearmor < $TESTDIR/password.$m.pgp.asc > $TESTDIR/password.$m.pgp
done

rm $TESTDIR/pass $TESTDIR/msg
