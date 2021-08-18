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
package org.pgpainless.sop;

import sop.SOP;
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

public class SOPImpl implements SOP {

    @Override
    public Version version() {
        return new VersionImpl();
    }

    @Override
    public GenerateKey generateKey() {
        return new GenerateKeyImpl();
    }

    @Override
    public ExtractCert extractCert() {
        return new ExtractCertImpl();
    }

    @Override
    public Sign sign() {
        return new SignImpl();
    }

    @Override
    public Verify verify() {
        return new VerifyImpl();
    }

    @Override
    public Encrypt encrypt() {
        return new EncryptImpl();
    }

    @Override
    public Decrypt decrypt() {
        return new DecryptImpl();
    }

    @Override
    public Armor armor() {
        return new ArmorImpl();
    }

    @Override
    public Dearmor dearmor() {
        return new DearmorImpl();
    }

    @Override
    public DetachInbandSignatureAndMessage detachInbandSignatureAndMessage() {
        return new DetachInbandSignatureAndMessageImpl();
    }
}
