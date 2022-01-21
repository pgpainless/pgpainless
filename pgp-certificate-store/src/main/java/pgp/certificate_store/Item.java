package pgp.certificate_store;

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

    /**
     * Return the fingerprint of the certificate.
     *
     * @return certificate fingerprint
     */
    public String getFingerprint() {
        return fingerprint;
    }

    /**
     * Return a tag used to check if the certificate was changed between retrievals.
     *
     * @return tag
     */
    public String getTag() {
        return tag;
    }

    /**
     * Return an {@link InputStream} containing the certificate data.
     *
     * @return data
     */
    public InputStream getData() {
        return data;
    }
}
