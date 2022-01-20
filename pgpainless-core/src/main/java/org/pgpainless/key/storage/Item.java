package org.pgpainless.key.storage;

import java.io.InputStream;

public class Item {

    private final String fingerprint;
    private final String tag;
    private final InputStream data;

    public Item(String fingerprint, String tag, InputStream data) {
        this.fingerprint = fingerprint;
        this.tag = tag;
        this.data = data;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getTag() {
        return tag;
    }

    public InputStream getData() {
        return data;
    }
}
