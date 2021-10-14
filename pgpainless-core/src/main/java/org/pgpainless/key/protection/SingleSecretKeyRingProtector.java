// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0
package org.pgpainless.key.protection;

import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * This interface assumes that all handled keys will use a single
 * realization of {@link SecretKeyRingProtector}.
 */
public interface SingleSecretKeyRingProtector {
    Map<Long, Exception> failedKeyIds = new HashMap<>();

    /**
     * Return a map that contains a key id of each key that was not unlocked.
     *
     * @return a map of key ids.
     */
    @Nonnull
    default Map<Long, Exception> getFailedKeyIds() {
        return failedKeyIds;
    }

    /**
     * Add a key id of some key that was not unlocked due to {@code e}
     *
     * @param keyId the key id
     * @param e     an instance of {@link Exception}
     */
    default void addFailedKeyId(long keyId, Exception e) {
        failedKeyIds.put(keyId, e);
    }
}
