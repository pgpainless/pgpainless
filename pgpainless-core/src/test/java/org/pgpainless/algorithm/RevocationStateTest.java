// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.junit.jupiter.api.Test;
import org.pgpainless.util.DateUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RevocationStateTest {

    @Test
    public void testNotRevoked() {
        RevocationState state = RevocationState.notRevoked();
        assertEquals(RevocationStateType.notRevoked, state.getType());
        assertTrue(state.isNotRevoked());
        assertFalse(state.isHardRevocation());
        assertFalse(state.isSoftRevocation());
        assertThrows(NoSuchElementException.class, state::getDate);
        assertEquals("notRevoked", state.toString());
    }

    @Test
    public void testHardRevoked() {
        RevocationState state = RevocationState.hardRevoked();
        assertEquals(RevocationStateType.hardRevoked, state.getType());
        assertTrue(state.isHardRevocation());
        assertFalse(state.isSoftRevocation());
        assertFalse(state.isNotRevoked());

        assertThrows(NoSuchElementException.class, state::getDate);
        assertEquals("hardRevoked", state.toString());
    }

    @Test
    public void testSoftRevoked() {
        Date date = DateUtil.parseUTCDate("2022-08-03 18:26:35 UTC");
        assertNotNull(date);

        RevocationState state = RevocationState.softRevoked(date);
        assertEquals(RevocationStateType.softRevoked, state.getType());
        assertTrue(state.isSoftRevocation());
        assertFalse(state.isHardRevocation());
        assertFalse(state.isNotRevoked());
        assertEquals(date, state.getDate());

        assertEquals("softRevoked (2022-08-03 18:26:35 UTC)", state.toString());
    }

    @Test
    public void orderTest() {
        assertEquals(RevocationState.notRevoked(), RevocationState.notRevoked());
        assertEquals(RevocationState.hardRevoked(), RevocationState.hardRevoked());
        Date now = new Date();
        assertEquals(RevocationState.softRevoked(now), RevocationState.softRevoked(now));

        assertEquals(1, RevocationState.softRevoked(now).compareTo(RevocationState.notRevoked()));

        assertEquals(0, RevocationState.notRevoked().compareTo(RevocationState.notRevoked()));
        assertEquals(0, RevocationState.hardRevoked().compareTo(RevocationState.hardRevoked()));
        assertTrue(RevocationState.hardRevoked().compareTo(RevocationState.notRevoked()) > 0);

        List<RevocationState> states = new ArrayList<>();
        RevocationState earlySoft = RevocationState.softRevoked(DateUtil.parseUTCDate("2000-05-12 10:44:01 UTC"));
        RevocationState laterSoft = RevocationState.softRevoked(DateUtil.parseUTCDate("2022-08-03 18:26:35 UTC"));
        RevocationState hard = RevocationState.hardRevoked();
        RevocationState not = RevocationState.notRevoked();
        RevocationState not2 = RevocationState.notRevoked();
        states.add(laterSoft);
        states.add(not);
        states.add(not2);
        states.add(hard);
        states.add(earlySoft);

        Collections.shuffle(states);
        Collections.sort(states);

        assertEquals(states, Arrays.asList(not, not2, laterSoft, earlySoft, hard));
    }

    @SuppressWarnings({"SimplifiableAssertion", "ConstantConditions", "EqualsWithItself", "EqualsBetweenInconvertibleTypes"})
    @Test
    public void equalsTest() {
        RevocationState rev = RevocationState.hardRevoked();
        assertFalse(rev.equals(null));
        assertTrue(rev.equals(rev));
        assertFalse(rev.equals("not a revocation"));
        RevocationState other = RevocationState.notRevoked();
        assertFalse(rev.equals(other));
    }
}
