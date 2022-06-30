// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CollectionUtilsTest {

    @Test
    public void testIteratorToList() {
        List<String> list = Arrays.asList("Hello", "World");
        Iterator<String> iterator = list.iterator();

        List<String> toList = CollectionUtils.iteratorToList(iterator);
        assertEquals(list, toList);
    }

    @Test
    public void testEmptyIteratorToList() {
        Iterator<String> emptyIterator = new Iterator<String>() {
            @Override
            public boolean hasNext() {
                return false;
            }

            @Override
            public String next() {
                throw new NoSuchElementException();
            }
        };

        List<String> list = CollectionUtils.iteratorToList(emptyIterator);
        assertTrue(list.isEmpty());
    }

    @Test
    public void testIteratorContains() {
        Iterator<String> iterator = Arrays.asList("Alpha", "Bravo", "Charlie", "Delta").iterator();
        assertTrue(CollectionUtils.contains(iterator,"Charlie"));
    }

    @Test
    public void testIteratorNotContains() {
        Iterator<String> iterator = Arrays.asList("Alpha", "Bravo", "Charlie", "Delta").iterator();
        assertFalse(CollectionUtils.contains(iterator,"Echo"));
    }

    @Test
    public void testMapStringsToNumbers() {
        Iterator<String> phonetics = Arrays.asList("Foxtrot", "Uniform", "Charlie", "Kilo").iterator();
        CollectionUtils.Mapper<String, Character> phoneticsMapper =
                item -> item.toUpperCase().charAt(0);
        Iterator<Character> characters = CollectionUtils.map(phonetics, phoneticsMapper);
        CollectionUtils.Reducer<Character, String> concat = new CollectionUtils.Reducer<Character, String>() {
            final StringBuilder sb = new StringBuilder();
            @Override
            public void accumulate(Character item) {
                sb.append(item);
            }

            @Override
            public String getResult() {
                return sb.toString();
            }
        };
        String explicit = CollectionUtils.reduce(characters, concat);
        assertEquals(rot13("SHPX"), explicit);
    }

    private String rot13(String string) {
        char[] chars = string.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (65 + ((chars[i] - 52) % 26));
        }
        return new String(chars);
    }

    @Test
    public void testAddAll() {
        List<String> list = new ArrayList<>(Arrays.asList("Alpha", "Bravo"));
        Iterator<String> iterator = Arrays.asList("Charlie", "Delta", "Echo").iterator();

        CollectionUtils.addAll(iterator, list);
        assertEquals(Arrays.asList("Alpha", "Bravo", "Charlie", "Delta", "Echo"), list);
    }
}
