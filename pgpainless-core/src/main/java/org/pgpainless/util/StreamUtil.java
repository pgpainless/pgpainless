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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class StreamUtil {

    /**
     * Pipe all data from the given {@link InputStream} to the given {@link OutputStream}.
     *
     * This utility method is required, since {@link org.bouncycastle.util.io.Streams#pipeAll(InputStream, OutputStream)}
     * internally uses {@link InputStream#read(byte[], int, int)} which silently swallows {@link IOException IOExceptions}.
     *
     * @see <a href="https://github.com/pgpainless/pgpainless/issues/159#issuecomment-886694555">Explanation</a>
     * @see <a href="https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/java/io/InputStream.java#L286">
     *     InputStream swallowing IOExceptions</a>
     *
     * @param inputStream input stream
     * @param outputStream output stream
     * @throws IOException io exceptions
     */
    public static void pipeAll(InputStream inputStream, OutputStream outputStream) throws IOException {
        do {
            int i = inputStream.read();
            if (i == -1) {
                break;
            }
            outputStream.write(i);
        } while (true);
    }

    /**
     * Drain an {@link InputStream} without calling {@link InputStream#read(byte[], int, int)}.
     *
     * @param inputStream input stream
     * @throws IOException io exception
     */
    public static void drain(InputStream inputStream) throws IOException {
        int i;
        do {
            i = inputStream.read();
        } while (i != -1);
    }
}
