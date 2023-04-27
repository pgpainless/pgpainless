#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SOP_DIR=$(realpath $SCRIPT_DIR/../../sop-java)
[ ! -d "$SOP_DIR" ] && echo "sop-java repository MUST be cloned next to pgpainless repo" && exit 1;
SRC_DIR=$SOP_DIR/sop-java-picocli/build/docs/manpage
[ ! -d "$SRC_DIR" ] && echo "No sop manpages found. Please run `gradle asciidoctor` in the sop-java repo." && exit 1;
DEST_DIR=$SCRIPT_DIR/packaging/man
mkdir -p $DEST_DIR

for page in $SRC_DIR/*
do
    SRC="${page##*/}"
    DEST="${SRC/sop/pgpainless-cli}"
    sed \
        -e 's#.\\"     Title: sop#.\\"     Title: pgpainless-cli#g' \
        -e 's/Manual: Sop Manual/Manual: PGPainless-CLI Manual/g' \
        -e 's/.TH "SOP/.TH "PGPAINLESS\\-CLI/g' \
        -e 's/"Sop Manual"/"PGPainless\\-CLI Manual"/g' \
        -e 's/\\fBsop/\\fBpgpainless\\-cli/g' \
        -e 's/sop/pgpainless\\-cli/g' \
        $page > $DEST_DIR/$DEST
done

