/*
 * Copyright 2021 Paul Schaub.
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
package sop;

import sop.operation.Armor;
import sop.operation.Dearmor;
import sop.operation.Decrypt;
import sop.operation.DetachInbandSignatureAndMessage;
import sop.operation.Encrypt;
import sop.operation.ExtractCert;
import sop.operation.GenerateKey;
import sop.operation.Sign;
import sop.operation.Verify;
import sop.operation.Version;

/**
 * Stateless OpenPGP Interface.
 */
public interface SOP {

    /**
     * Get information about the implementations name and version.
     *
     * @return version
     */
    Version version();

    /**
     * Generate a secret key.
     * Customize the operation using the builder {@link GenerateKey}.
     *
     * @return builder instance
     */
    GenerateKey generateKey();

    /**
     * Extract a certificate (public key) from a secret key.
     * Customize the operation using the builder {@link ExtractCert}.
     *
     * @return builder instance
     */
    ExtractCert extractCert();

    /**
     * Create detached signatures.
     * Customize the operation using the builder {@link Sign}.
     *
     * @return builder instance
     */
    Sign sign();

    /**
     * Verify detached signatures.
     * Customize the operation using the builder {@link Verify}.
     *
     * @return builder instance
     */
    Verify verify();

    /**
     * Encrypt a message.
     * Customize the operation using the builder {@link Encrypt}.
     *
     * @return builder instance
     */
    Encrypt encrypt();

    /**
     * Decrypt a message.
     * Customize the operation using the builder {@link Decrypt}.
     *
     * @return builder instance
     */
    Decrypt decrypt();

    /**
     * Convert binary OpenPGP data to ASCII.
     * Customize the operation using the builder {@link Armor}.
     *
     * @return builder instance
     */
    Armor armor();

    /**
     * Converts ASCII armored OpenPGP data to binary.
     * Customize the operation using the builder {@link Dearmor}.
     *
     * @return builder instance
     */
    Dearmor dearmor();

    DetachInbandSignatureAndMessage detachInbandSignatureAndMessage();
}
