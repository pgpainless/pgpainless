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
package org.pgpainless.util;

import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;

/**
 * Factory to create configured {@link ArmoredOutputStream ArmoredOutputStreams}.
 */
public class ArmoredOutputStreamFactory {

    public static final String VERSION = "PGPainless";

    public static ArmoredOutputStream get(OutputStream outputStream) {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
        armoredOutputStream.setHeader(ArmoredOutputStream.VERSION_HDR, VERSION);
        return armoredOutputStream;
    }
}
