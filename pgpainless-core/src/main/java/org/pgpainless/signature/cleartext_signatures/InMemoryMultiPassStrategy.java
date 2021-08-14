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
package org.pgpainless.signature.cleartext_signatures;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Implementation of the {@link MultiPassStrategy}.
 * This class keeps the read data in memory by caching the data inside a {@link ByteArrayOutputStream}.
 *
 * Note, that this class is suitable and efficient for processing small amounts of data.
 * For larger data like encrypted files, use of the {@link WriteToFileMultiPassStrategy} is recommended to
 * prevent {@link OutOfMemoryError OutOfMemoryErrors} and other issues.
 */
public class InMemoryMultiPassStrategy implements MultiPassStrategy {

    private final ByteArrayOutputStream cache = new ByteArrayOutputStream();

    @Override
    public ByteArrayOutputStream getMessageOutputStream() {
        return cache;
    }

    @Override
    public ByteArrayInputStream getMessageInputStream() {
        return new ByteArrayInputStream(getBytes());
    }

    public byte[] getBytes() {
        return getMessageOutputStream().toByteArray();
    }
}
