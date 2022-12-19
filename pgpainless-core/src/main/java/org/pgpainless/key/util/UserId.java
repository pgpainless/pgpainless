// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class UserId implements CharSequence {

    private static final Pattern emailPattern = Pattern.compile("(?:[\\p{L}\\u0900-\\u097F0-9!#\\$%&'*+/=?^_`{|}~-]+(?:\\.[\\p{L}\\u0900-\\u097F0-9!#\\$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-" +
            "\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[\\p{L}\\u0900-\\u097F0-9](?:[\\p{L}\\u0900-\\u097F0-9" +
            "-]*[\\p{L}\\u0900-\\u097F0-9])?\\.)+[\\p{L}\\u0900-\\u097F0-9](?:[\\p{L}\\u0900-\\u097F0-9-]*[\\p{L}\\u0900-\\u097F0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" +
            "\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[$\\p{L}\\u0900-\\u097F0-9-]*[\\p{L}\\u0900-\\u097F0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f" +
            "\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)])");

    private static final Pattern nameAddrPattern = Pattern.compile("^((?<name>.+?)\\s)?(\\((?<comment>.+?)\\)\\s)?(<(?<email>.+?)>)?$");

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

        public Builder withName(@Nonnull String name) {
            this.name = name;
            return this;
        }

        public Builder withComment(@Nonnull String comment) {
            this.comment = comment;
            return this;
        }

        public Builder withEmail(@Nonnull String email) {
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

    public static UserId parse(@Nonnull String string) {
        Builder builder = newBuilder();
        string = string.trim();
        Matcher matcher = nameAddrPattern.matcher(string);
        if (matcher.find()) {
            String name = matcher.group("name");
            String comment = matcher.group("comment");
            String mail = matcher.group("email");
            matcher = emailPattern.matcher(mail);
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Malformed email address");
            }

            if (name != null) {
                builder.withName(name);
            }
            if (comment != null) {
                builder.withComment(comment);
            }
            builder.withEmail(mail);
        } else {
            matcher = emailPattern.matcher(string);
            if (matcher.matches()) {
                builder.withEmail(string);
            } else {
                throw new IllegalArgumentException("Malformed email address");
            }
        }
        return builder.build();
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
        return new UserId(null, null, email);
    }

    public static UserId nameAndEmail(@Nonnull String name, @Nonnull String email) {
        return new UserId(name, null, email);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder(name, comment, email);
    }

    public String getName() {
        return getName(false);
    }

    public String getName(boolean preserveQuotes) {
        if (name == null || name.isEmpty()) {
            return name;
        }

        if (name.startsWith("\"")) {
            if (preserveQuotes) {
                return name;
            }
            String withoutQuotes = name.substring(1);
            if (withoutQuotes.endsWith("\"")) {
                withoutQuotes = withoutQuotes.substring(0, withoutQuotes.length() - 1);
            }
            return withoutQuotes;
        }
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
            sb.append(getName(true));
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

    public static int compare(@Nullable UserId o1, @Nullable UserId o2, @Nonnull Comparator<UserId> comparator) {
        return comparator.compare(o1, o2);
    }

    public static class DefaultComparator implements Comparator<UserId> {

        @Override
        public int compare(UserId o1, UserId o2) {
            if (o1 == o2) {
                return 0;
            }
            if (o1 == null) {
                return -1;
            }
            if (o2 == null) {
                return 1;
            }

            NullSafeStringComparator c = new NullSafeStringComparator();
            int cName = c.compare(o1.getName(), o2.getName());
            if (cName != 0) {
                return cName;
            }

            int cComment = c.compare(o1.getComment(), o2.getComment());
            if (cComment != 0) {
                return cComment;
            }

            return c.compare(o1.getEmail(), o2.getEmail());
        }
    }

    public static class DefaultIgnoreCaseComparator implements Comparator<UserId> {

        @Override
        public int compare(UserId o1, UserId o2) {
            if (o1 == o2) {
                return 0;
            }
            if (o1 == null) {
                return -1;
            }
            if (o2 == null) {
                return 1;
            }

            NullSafeStringComparator c = new NullSafeStringComparator();
            int cName = c.compare(lower(o1.getName()), lower(o2.getName()));
            if (cName != 0) {
                return cName;
            }

            int cComment = c.compare(lower(o1.getComment()), lower(o2.getComment()));
            if (cComment != 0) {
                return cComment;
            }

            return c.compare(lower(o1.getEmail()), lower(o2.getEmail()));
        }

        private static String lower(String string) {
            return string == null ? null : string.toLowerCase();
        }
    }

    private static class NullSafeStringComparator implements Comparator<String> {

        @Override
        public int compare(String o1, String o2) {
            // noinspection StringEquality
            if (o1 == o2) {
                return 0;
            }
            if (o1 == null) {
                return -1;
            }
            if (o2 == null) {
                return 1;
            }
            return o1.compareTo(o2);
        }
    }
}
