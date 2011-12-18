/* Copyright 2011 Cloudseal O†
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
package com.cloudseal.spring.client.namespace;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.internal.matchers.TypeSafeMatcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

public class IsCollection<T> extends TypeSafeMatcher<Collection<T>> {
    private static enum Method {ANY_ORDER, SAME_ORDER}

    private final Collection<T> expected;
    private final Method method;

    private IsCollection(final Collection<T> expected, final Method method) {
        this.expected = expected;
        this.method = method;
    }

    @Override
    public boolean matchesSafely(Collection<T> given) {
        switch (method) {
            case ANY_ORDER:
                return matchesAnyOrder(given);
            case SAME_ORDER:
            default:
                return matchesSameOrder(given);
        }
    }

    @Override
    public void describeTo(Description description) {
        final StringBuilder builder = new StringBuilder();
        for (final T item : expected) {
            if (builder.length() != 0)
                builder.append(", ");
            builder.append(item.toString());
        }
        builder.insert(0, "<[");
        builder.append("]>");
        description.appendText(builder.toString());
    }

    public static <T> Matcher<Collection<T>> hasAnyOrder(Collection<T> collection) {
        return new IsCollection<T>(collection, Method.ANY_ORDER);
    }

    public static <T> Matcher<Collection<T>> hasSameOrder(Collection<T> collection) {
        return new IsCollection<T>(collection, Method.SAME_ORDER);
    }

    public boolean matchesAnyOrder(Collection<T> given) {
        final Collection<T> copy = new ArrayList<T>(expected);
        for (T item : given) {
            if (!copy.remove(item))
                return false;
        }
        return copy.isEmpty();
    }

    public boolean matchesSameOrder(Collection<T> given) {
        final Iterator<T> expectedIterator = expected.iterator();
        final Iterator<T> givenIterator = given.iterator();
        while (expectedIterator.hasNext() && givenIterator.hasNext()) {
            if (!expectedIterator.next().equals(givenIterator.next()))
                return false;
        }
        return !expectedIterator.hasNext() && !givenIterator.hasNext();
    }
}
