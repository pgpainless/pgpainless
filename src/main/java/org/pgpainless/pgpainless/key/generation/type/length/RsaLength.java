/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.pgpainless.key.generation.type.length;

public enum RsaLength implements KeyLength {
    @Deprecated
    _1024(1024),
    @Deprecated
    _2048(2048),
    _3072(3072),
    _4096(4096),
    _8192(8192),
    ;

    private final int length;

    RsaLength(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }
}
