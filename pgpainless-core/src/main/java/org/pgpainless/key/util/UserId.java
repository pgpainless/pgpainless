// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class UserId implements CharSequence {
    public static final class Builder {
        private String name;
        private String comment;
        private String email;

        private Builder() {
        }

        private Builder(String name, String comment, String email) {
            this.name = name;
            this.comment = comment;
            this.email = email;
        }

        public Builder withName(String name) {
            checkNotNull("name", name);
            this.name = name;
            return this;
        }

        public Builder withComment(String comment) {
            checkNotNull("comment", comment);
            this.comment = comment;
            return this;
        }

        public Builder withEmail(String email) {
            checkNotNull("email", email);
            this.email = email;
            return this;
        }

        public Builder noName() {
            name = null;
            return this;
        }

        public Builder noComment() {
            comment = null;
            return this;
        }

        public Builder noEmail() {
            email = null;
            return this;
        }

        public UserId build() {
            return new UserId(name, comment, email);
        }
    }

    private final String name;
    private final String comment;
    private final String email;
    private long hash = Long.MAX_VALUE;

    private UserId(@Nullable String name, @Nullable String comment, @Nullable String email) {
        this.name = name == null ? null : name.trim();
        this.comment = comment == null ? null : comment.trim();
        this.email = email == null ? null : email.trim();
    }

    public static UserId onlyEmail(@Nonnull String email) {
        checkNotNull("email", email);
        return new UserId(null, null, email);
    }

    public static UserId nameAndEmail(@Nonnull String name, @Nonnull String email) {
        checkNotNull("name", name);
        checkNotNull("email", email);
        return new UserId(name, null, email);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder(name, comment, email);
    }

    public String getName() {
        return name;
    }

    public String getComment() {
        return comment;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public int length() {
        return toString().length();
    }

    @Override
    public char charAt(int i) {
        return toString().charAt(i);
    }

    @Override
    public @Nonnull CharSequence subSequence(int i, int i1) {
        return toString().subSequence(i, i1);
    }

    @Override
    public @Nonnull String toString() {
        StringBuilder sb = new StringBuilder();
        if (name != null && !name.isEmpty()) {
            sb.append(name);
        }
        if (comment != null && !comment.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append('(').append(comment).append(')');
        }
        if (email != null && !email.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append('<').append(email).append('>');
        }
        return sb.toString();
    }

    /**
     * Returns a string representation of the object.
     * @return a string representation of the object.
     * @deprecated use {@link #toString()} instead.
     */
    @Deprecated
    public String asString() {
        return toString();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) return false;
        if (o == this) return true;
        if (!(o instanceof UserId)) return false;
        final UserId other = (UserId) o;
        return isEqualComponent(name, other.name, false)
                && isEqualComponent(comment, other.comment, false)
                && isEqualComponent(email, other.email, true);
    }

    @Override
    public int hashCode() {
        if (hash != Long.MAX_VALUE) {
            return (int) hash;
        } else {
            int hashCode = 7;
            hashCode = 31 * hashCode + (name == null ? 0 : name.hashCode());
            hashCode = 31 * hashCode + (comment == null ? 0 : comment.hashCode());
            hashCode = 31 * hashCode + (email == null ? 0 : email.toLowerCase().hashCode());
            this.hash = hashCode;
            return hashCode;
        }
    }

    private static boolean isEqualComponent(String value, String otherValue, boolean ignoreCase) {
        final boolean valueIsNull = (value == null);
        final boolean otherValueIsNull = (otherValue == null);
        return (valueIsNull && otherValueIsNull)
                || (!valueIsNull && !otherValueIsNull
                && (ignoreCase ? value.equalsIgnoreCase(otherValue) : value.equals(otherValue)));
    }

    private static void checkNotNull(String paramName, String value) {
        if (value == null) {
            throw new IllegalArgumentException(paramName + " must be not null");
        }
    }
}
