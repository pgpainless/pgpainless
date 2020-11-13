/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.util;

public class UserId implements CharSequence {

    private final String name;
    private final String comment;
    private final String email;

    public UserId(String name, String comment, String email) {
        this.name = name;
        this.comment = comment;
        this.email = email;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (name != null) {
            sb.append(name);
        }
        if (comment != null) {
            sb.append(" (").append(comment).append(')');
        }
        if (email != null) {
            sb.append(sb.length() != 0 ? " <" : '<').append(email).append('>');
        }
        return sb.toString();
    }

    public static UserId onlyEmail(String email) {
        if (email == null) {
            throw new IllegalArgumentException("Email must not be null.");
        }
        return new UserId(null, null, email);
    }

    public static WithComment withName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Name must not be null.");
        }
        return new WithComment(name);
    }

    public static class WithComment {

        private final String name;

        public WithComment(String name) {
            this.name = name;
        }

        public WithEmail withComment(String comment) {
            if (comment == null) {
                throw new IllegalArgumentException("Comment must not be null.");
            }
            return new WithEmail(name, comment);
        }

        public WithEmail noComment() {
            return new WithEmail(name, null);
        }

        public UserId build() {
            return new UserId(name, null, null);
        }
    }

    public static class WithEmail {

        private final String name;
        private final String comment;

        public WithEmail(String name, String comment) {
            this.name = name;
            this.comment = comment;
        }

        public UserId withEmail(String email) {
            if (email == null) {
                throw new IllegalArgumentException("Email must not be null.");
            }
            return new UserId(name, comment, email);
        }

        public UserId noEmail() {
            return new UserId(name, comment, null);
        }
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
    public CharSequence subSequence(int i, int i1) {
        return toString().subSequence(i, i1);
    }

}
