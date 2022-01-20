package org.pgpainless.key.storage;

import javax.annotation.Nullable;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Merge a given certificate (update) with an existing certificate.
 */
public interface MergeCallback {

    /**
     * Merge the given certificate data with the existing certificate and return the result.
     *
     * If no existing certificate is found (i.e. existing is null), this method returns the binary representation of data.
     *
     * @param data input stream containing the certificate
     * @param existing optional input stream containing an already existing copy of the certificate
     * @return output stream containing the binary representation of the merged certificate
     */
    OutputStream merge(InputStream data, @Nullable InputStream existing);

}
