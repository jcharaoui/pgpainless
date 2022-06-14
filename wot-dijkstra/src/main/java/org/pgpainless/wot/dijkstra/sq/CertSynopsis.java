package org.pgpainless.wot.dijkstra.sq;

import org.pgpainless.key.OpenPgpFingerprint;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class CertSynopsis {

    private final OpenPgpFingerprint fingerprint;
    private final Date expirationTime;
    private final boolean revoked;
    private final Set<String> userIds;

    public CertSynopsis(OpenPgpFingerprint fingerprint,
                        Date expirationTime,
                        boolean revoked,
                        Set<String> userIds) {
        this.fingerprint = fingerprint;
        this.expirationTime = expirationTime;
        this.revoked = revoked;
        this.userIds = userIds;
    }

    public OpenPgpFingerprint getFingerprint() {
        return fingerprint;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public Set<String> userIds() {
        return new HashSet<>(userIds);
    }
}
