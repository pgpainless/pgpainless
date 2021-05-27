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
package org.pgpainless.algorithm;

public enum EncryptionPurpose {
    /**
     * The stream will encrypt communication that goes over the wire.
     * Eg. EMail, Chat...
     */
    COMMUNICATIONS,
    /**
     * The stream will encrypt data that is stored on disk.
     * Eg. Encrypted backup...
     */
    STORAGE,
    /**
     * The stream will use keys with either flags to encrypt the data.
     */
    STORAGE_AND_COMMUNICATIONS
}
