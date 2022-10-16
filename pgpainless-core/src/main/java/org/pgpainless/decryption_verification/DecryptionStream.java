package org.pgpainless.decryption_verification;

import javax.annotation.Nonnull;

public abstract class DecryptionStream extends CloseForResultInputStream {
    public DecryptionStream(@Nonnull OpenPgpMetadata.Builder resultBuilder) {
        super(resultBuilder);
    }
}
