/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeySpec;

public interface KeyRingEditorInterface {

    /**
     * Add a user-id to the primary key of the key ring.
     *
     * @param userId user-id
     * @return the builder
     */
    KeyRingEditorInterface addUserId(String userId);

    /**
     * Remove a user-id from the primary key of the key ring.
     *
     * @param userId exact user-id to be removed
     * @return the builder
     */
    KeyRingEditorInterface deleteUserId(String userId);

    /**
     * Add a subkey to the key ring.
     * The subkey will be generated from the provided {@link KeySpec}.
     *
     * @param keySpec key specification
     * @return the builder
     */
    KeyRingEditorInterface addSubKey(KeySpec keySpec);

    /**
     * Delete a subkey from the key ring.
     * The subkey with the provided fingerprint will be remove from the key ring.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be removed
     * @return the builder
     */
    KeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint);

    /**
     * Delete a subkey from the key ring.
     * The subkey with the provided key-id will be removed from the key ring.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param subKeyId id of the subkey
     * @return the builder
     */
    KeyRingEditorInterface deleteSubKey(long subKeyId);

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided fingerprint will be revoked.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be revoked
     * @return the builder
     */
    KeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint);

    /**
     * Revoke the subkey binding sugnature of a subkey.
     * The subkey with the provided key-id will be revoked.
     * If no suitable subkey is found, q {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param subKeyId id of the subkey
     * @return the builder
     */
    KeyRingEditorInterface revokeSubKey(long subKeyId);

    /**
     * Return the {@link PGPSecretKeyRing}
     * @return the key
     */
    PGPSecretKeyRing done();
}
