// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Arrays;

import static org.pgpainless.util.BCUtil.constantTimeAreEqual;

public class Passphrase {

    public final Object lock = new Object();

    private final char[] chars;
    private boolean valid = true;

    /**
     * Passphrase for keys etc.
     *
     * @param chars may be null for empty passwords.
     */
    public Passphrase(@Nullable char[] chars) {
        if (chars == null) {
            this.chars = null;
        } else {
            char[] trimmed = removeTrailingAndLeadingWhitespace(chars);
            if (trimmed.length == 0) {
                this.chars = null;
            } else {
                this.chars = trimmed;
            }
        }
    }

    /**
     * Return a copy of the passed in char array, with leading and trailing whitespace characters removed.
     *
     * @param chars char array
     * @return copy of char array with leading and trailing whitespace characters removed
     */
    private static char[] removeTrailingAndLeadingWhitespace(char[] chars) {
        int i = 0;
        while (i < chars.length && isWhitespace(chars[i])) {
            i++;
        }
        int j = chars.length - 1;
        while (j >= i && isWhitespace(chars[j])) {
            j--;
        }

        char[] trimmed = new char[chars.length - i - (chars.length - 1 - j)];
        System.arraycopy(chars, i, trimmed, 0, trimmed.length);

        return trimmed;
    }

    /**
     * Return true, if the passed in char is a whitespace symbol (space, newline, tab).
     *
     * @param xar char
     * @return true if whitespace
     */
    private static boolean isWhitespace(char xar) {
        return xar == ' ' || xar == '\n' || xar == '\t';
    }

    /**
     * Create a {@link Passphrase} from a {@link String}.
     *
     * @param password password
     * @return passphrase
     */
    public static Passphrase fromPassword(@Nonnull String password) {
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
     * Return true if the passphrase represents no password.
     *
     * @return empty
     */
    public boolean isEmpty() {
        synchronized (lock) {
            return valid && chars == null;
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

    @Override
    public int hashCode() {
        if (getChars() == null) {
            return 0;
        }
        return new String(getChars()).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Passphrase)) {
            return false;
        }
        Passphrase other = (Passphrase) obj;
        return (getChars() == null && other.getChars() == null) ||
                constantTimeAreEqual(getChars(), other.getChars());
    }
}
