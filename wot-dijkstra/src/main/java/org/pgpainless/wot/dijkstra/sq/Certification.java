package org.pgpainless.wot.dijkstra.sq;

import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.graalvm.compiler.nodes.calc.IntegerDivRemNode;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

import java.util.Date;
import java.util.List;

public class Certification {

    private final CertSynopsis issuer;
    private final CertSynopsis target;
    private final Optional<String> userId;

    private final Date creationTime;
    private final Optional<Date> expirationTime;
    private final boolean exportable;
    private final int trustAmount;
    private final int trustDepth;
    private final RegexSet regex;

    public Certification(
            CertSynopsis issuer,
            CertSynopsis target,
            Optional<String> userId,
            Date creationTime,
            Optional<Date> expirationTime,
            boolean exportable,
            int trustAmount,
            int trustDepth,
            RegexSet regex) {
        this.issuer = issuer;
        this.target = target;
        this.userId = userId;
        this.creationTime = creationTime;
        this.expirationTime = expirationTime;
        this.exportable = exportable;
        this.trustAmount=  trustAmount;
        this.trustDepth = trustDepth;
        this.regex = regex;
    }

    public Certification(CertSynopsis issuer,
                         Optional<String> targetUserId,
                         CertSynopsis target,
                         Date creationTime) {
        this.issuer = issuer;
        this.target = target;
        this.userId = targetUserId;
        this.creationTime = creationTime;

        this.expirationTime = Optional.empty();
        this.exportable = true;
        this.trustDepth = 0;
        this.trustAmount = 120;
        this.regex = RegexSet.wildcard();
    }

    public Certification(CertSynopsis issuer,
                         Optional<String> targetUserId,
                         CertSynopsis target,
                         PGPSignature signature) {
        this.issuer = issuer;
        this.target = target;
        this.userId = targetUserId;
        this.creationTime = SignatureSubpacketsUtil.getSignatureCreationTime(signature).getTime();
        this.expirationTime = Optional.maybe(SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature));
        Exportable exportablePacket = SignatureSubpacketsUtil.getExportableCertification(signature);
        this.exportable = exportablePacket == null || exportablePacket.isExportable();
        TrustSignature trustSignaturePacket = SignatureSubpacketsUtil.getTrustSignature(signature);
        if (trustSignaturePacket == null) {
            this.trustDepth = 0;
            this.trustAmount = 120;
        } else {
            this.trustDepth = trustSignaturePacket.getDepth();
            this.trustAmount = trustSignaturePacket.getTrustAmount();
        }
        List<RegularExpression> regularExpressionList = SignatureSubpacketsUtil.getRegularExpressions(signature);
        this.regex = RegexSet.fromList(regularExpressionList);
    }

    public CertSynopsis getIssuer() {
        return issuer;
    }

    public CertSynopsis getTarget() {
        return target;
    }

    public Optional<String> getUserId() {
        return userId;
    }
}
