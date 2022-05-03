package org.pgpainless.wot.dijkstra;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

public class Node {

    private PGPPublicKeyRing item;

    public long getCertificateKeyId() {
        return item.getPublicKey().getKeyID();
    }
}
