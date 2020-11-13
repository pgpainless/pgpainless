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
package org.pgpainless.key;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.pgpainless.key.util.UserId;

public class UserIdTest {

    @Test(expected = IllegalArgumentException.class)
    public void throwForNullName() {
        UserId.withName(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void throwForNullComment() {
        UserId.withName("foo")
                .withComment(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void throwForNullEmail() {
        UserId.withName("foo")
                .withComment("bar")
                .withEmail(null);
    }

    @Test
    public void testFormatOnlyName() {
        assertEquals(
                "Juliet Capulet",
                UserId.withName("Juliet Capulet")
                        .build().toString());
    }

    @Test
    public void testFormatNameAndComment() {
        assertEquals(
                "Juliet Capulet (from the play)",
                UserId.withName("Juliet Capulet")
                        .withComment("from the play")
                        .noEmail().toString());
    }

    @Test
    public void testFormatNameCommentAndMail() {
        assertEquals("Juliet Capulet (from the play) <juliet@capulet.lit>",
                UserId.withName("Juliet Capulet")
                        .withComment("from the play")
                        .withEmail("juliet@capulet.lit")
                        .toString());
    }

    @Test
    public void testFormatNameAndEmail() {
        assertEquals("Juliet Capulet <juliet@capulet.lit>",
                UserId.withName("Juliet Capulet")
                        .noComment()
                        .withEmail("juliet@capulet.lit")
                        .toString());
    }
}
