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
package org.pgpainless.util;

import javax.annotation.Nullable;
import java.util.Arrays;

public class Passphrase {

    private final Object lock = new Object();

    private final char[] chars;
    private boolean valid = true;

    /**
     * Passphrase for keys etc.
     *
     * @param chars may be null for empty passwords.
     */
    public Passphrase(@Nullable char[] chars) {
        this.chars = chars;
    }

    /**
     * Create a {@link Passphrase} from a {@link String}.
     *
     * @param password password
     * @return passphrase
     */
    public static Passphrase fromPassword(String password) {
        return new Passphrase(password.toCharArray());
    }

    /**
     * Overwrite the char array with spaces and mark the {@link Passphrase} as invalidated.
     */
    public void clear() {
        synchronized (lock) {
            if (chars != null) {
                Arrays.fill(chars, ' ');
            }
            valid = false;
        }
    }

    /**
     * Return a copy of the underlying char array.
     * A return value of {@code null} represents no password.
     *
     * @return passphrase chars.
     *
     * @throws IllegalStateException in case the password has been cleared at this point.
     */
    public @Nullable char[] getChars() {
        synchronized (lock) {
            if (!valid) {
                throw new IllegalStateException("Passphrase has been cleared.");
            }

            if (chars == null) {
                return null;
            }

            char[] copy = new char[chars.length];
            System.arraycopy(chars, 0, copy, 0, chars.length);
            return copy;
        }
    }

    /**
     * Return true if the passphrase has not yet been cleared.
     *
     * @return valid
     */
    public boolean isValid() {
        synchronized (lock) {
            return valid;
        }
    }

    /**
     * Represents a {@link Passphrase} instance that represents no password.
     *
     * @return empty passphrase
     */
    public static Passphrase emptyPassphrase() {
        return new Passphrase(null);
    }
}
