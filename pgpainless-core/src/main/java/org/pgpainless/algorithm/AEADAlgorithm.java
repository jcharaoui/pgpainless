// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

public enum AEADAlgorithm {

    EAX(1, 16, 16),
    OCB(2, 15, 16),
    GCM(3, 12, 16),
    ;

    private static final Map<Integer, AEADAlgorithm> MAP = new HashMap<>();

    private final int id;
    private final int ivLen;
    private final int tagLen;

    AEADAlgorithm(int id, int ivLen, int tagLen) {
        this.id = id;
        this.ivLen = ivLen;
        this.tagLen = tagLen;
    }

    @Nullable
    public static AEADAlgorithm fromId(int algorithmId) {
        return MAP.get(algorithmId);
    }

    @Nonnull
    public static AEADAlgorithm requireFromId(int algorithmId) {
        AEADAlgorithm algorithm = fromId(algorithmId);
        if (algorithm == null) {
            throw new NoSuchElementException("No AEAD Algorithm found for id " + algorithmId);
        }
        return algorithm;
    }

    public int getAlgorithmId() {
        return id;
    }

    public int getIvLength() {
        return ivLen;
    }

    public int getTagLength() {
        return tagLen;
    }
}
