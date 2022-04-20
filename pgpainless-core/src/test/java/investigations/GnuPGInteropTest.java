// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.Passphrase;

public class GnuPGInteropTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQWGBGJeAz0BDADMCFD4bbTFyJJghhoYf93buL8bJShM+YU5EyAdF644MU9U/tqs\n" +
            "UuOWd8a10D3/mIy2kdG/hAqGHVNGOUfG8PJSo41zsdo1UDdT1OK/Jq9hnqOT7oir\n" +
            "chh9Y49LLt26dazO9qIy/6Ykek+JBRODi4qzqBKSE1QhKz3vvyCYfDCTNoKHKSmM\n" +
            "SHkKN6NvVLoSLlB3RoMXWnSB3Ss8H15ktObSQV6lxqNHpuaAPE5CVFCAnaWaSVcE\n" +
            "uuDdA6Fyook84Xilzhmct+7XFSYahwzBRTLJx5KPxLpclE0e/I4YKfZ8cgJvsyo+\n" +
            "IAsCvzySFztne/dbI6fVc4wYN1wHeASQM+FmakEy4tD5G3PsFnUM4r52NoWanhlP\n" +
            "j99clB4d3EaN3ZvOFBopw8fF6L4fPiXCVRzsTOHIrpX/F0LhvDw3j4qxoCDNBr1v\n" +
            "8aMnapYrGmDmntsgkBy7uDANPhO50M8fOxRXmSUR6bv9hhvftK2Ff6Z+YDkSCkTk\n" +
            "AhFvxN5GeWRWZeUAEQEAAf4HAwIFo42Ds1FYIPKXER41FgJRcb6xveYTYpcOCaBG\n" +
            "quM6m+9/u0hmUKLBA3F6rxWBo9Nz+pyp2BsAcAPshm3Jof6FczLZf3kMi36lJb/H\n" +
            "1kgEyJiw2h6S+evLwjuzFhFY2eMXVisfV+ngf23p82ruW2ip1ZEvagAzDwWJuUsB\n" +
            "4NwUOg8PeowYgKcB/pZzfvAbzX9FYgfq29yZZDAkvatQaUNJ39z13Qfv+Jv01Inh\n" +
            "GojurVjdwScoH8TQvkFRVYl32oHGY1e2QBKis6Iuk7+V4O43mJ0//GRUl3wrHdA3\n" +
            "R/x3v7H8OHtgkxkTJv+FSk/qf+NKndQr+byq0AIoB8iClEIgP1CP5sbh541RaLPm\n" +
            "agDCzNwTnKJ6lmrh6kVzpyhGLGeQJ3cDKOftWEEtQpUYBMbhRdKu+9S2pty5WyPH\n" +
            "gtV+cpSPQbr7WCYcvcvdbc+0wnsA/QP4viLWCXJBsc3XbG9APIXlQOQBbPss44AK\n" +
            "xKqY+iwi99U9N8e5wsK3VgFHCU14QSCXIQQsllRcZlFqtYMc/fmMk/vWt3WtbO9Z\n" +
            "gdZf1bAV8JZFo8uD9v7XKPH3ZWrU9w9zZBJOZGa1hgzwQJTjDOu1w5WGszV6yaPk\n" +
            "I5iIi1WF+3WLCH4GPuK/7iurXxeyYzPGhWCVDWCwnE4Fd+ET4TpZIXHqUTW/+Axo\n" +
            "td3hCMwo4PcgcIhw0ygzABilxA+fnrgVGcfppHuVkvULCS5w2elueZlaNiCWFiH0\n" +
            "kRfQ+b1o5fgBaq3VpA6cjmogX411mfaIULc/85evp3Sin3B143LhDzpFHxUvX7M3\n" +
            "ITNWB1LWN5KiXKDew9JV+Ge7X9HIxzrMoSsINuBxIN3iC/tMld1HPBtIhpL+g1PQ\n" +
            "IOVlFsAOgm+j9raQ0Fmua5rX5graldfGwt7pu5Qfm+/r54abBb2WdF/rueSpPoQ8\n" +
            "LH8+cFW5xOQ6WJYecHtgEv5Wo67/14+Lxd/sOas6TNH0N64VWHLb6jYjLe3XrTUQ\n" +
            "Z19MwldQsV95JLK8dh/ETpJHxlwHifoy5w7pnYs7IvDzs3c7mkFXBtOg2rPFLexZ\n" +
            "xfqQcfY/fVqybtUNwW18mdSHFmF5PntzqSig+Uo2HcBCcxKLXfL1lFbSFymU9J/F\n" +
            "dKofDhFLnYaQYU7pP+hQkOS655I/hRhIGazU/CoRaCzR9iKprdSvQmtnJaFIKit6\n" +
            "c4f45VGRRGAa14L6eOEvRkZXiy1ENokBZXVtp/hGl5Huck/QoOQ6ICS+9nOItWRg\n" +
            "YNp22q/ni0w/4TH3z4sqAHnoBO8/OEjvwhJG+W/3PH+cec5T2QIHYjyp2vAboneK\n" +
            "uab9H9jrN2ZgTRctj66XTfvwMXYTrQQgvLQxQ29saW4gV2lsbGlhbXMgPGNvbGlu\n" +
            "LndpbGxpYW1zLnNlYXR0bGVAZ21haWwuY29tPokB1AQTAQIAPhYhBCUAupaxZmMR\n" +
            "tjpx7sw4aYcbHpA7BQJiXgM9AhsDBQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4B\n" +
            "AheAAAoJEMw4aYcbHpA7Bj0MAKsKrWEPNdQbxSIhiMTDQDa+mrf5Zzz82q+ydNyh\n" +
            "QXIdm4ne5mx1RkGKcwE/gnH0QV7nPEeOiMPQ1T1gz1VfgVPFpSwPwcyJevPDvFKi\n" +
            "8lse/eTOF1zbtJOvTwFYzU509coRP6MAjsljga9s4S1niUR13U8nK2iZWISysEQ+\n" +
            "v4whRfuaq0aI/MQQThfvZJpT2Mg1nt2u7yG7n1jePAM9r+CpPMoo1elnonFzm8Re\n" +
            "E8dF3o31mm9PfljV+GnsPyZLZ9JNPDGWKcfjOS9YV55rgkHG9lNfnXcW9z5YrTpW\n" +
            "r1siwFuCrRkG+a50zcVXLZgo3zQfY7rxEhlDro1kCVUfktcXa+7HGXE8OAdVVyef\n" +
            "SyQ9uUs2b53R2Oei3lD9fbkpxqpnLgVw/xUQBVDLn68b5zCtDfsUsI4JSCo9a/12\n" +
            "NE9LiSzzglKqtap4dWw4B+G1lvKl1uHaK+l8mVVj5HxVtyTLkIW2ShB6Id83F0Wl\n" +
            "dOFvUkfGjdZR+DQeQ1OPFI0Sx50FhgRiXgM9AQwAvrXWKxERqXV2mN1cNlAuaSfZ\n" +
            "WaexnbPbThlnJLKtJLUZQ9e3fq44DvwVJP7kCxcnwj7wQSyzOghInS7gUEVZ2mI4\n" +
            "cWZtL8rEwtUQ/7YxpgMNd1Xg84ACkvDjuzrR90NR2NzgMOhyh06SU+nvfdShk7nv\n" +
            "KrqyQK1XdM1z6VhRWyu456tF49skZ1bckO2Ay4FqfpfYI51WDH7dxrb7zYc6CATP\n" +
            "epKbZDb5V2i1BCWSzG1HrhWmC8zLyumnzy9w7idZ3vjfdZt+NhBlWgBF1wEV8Sui\n" +
            "08OEfepIc03sBOgIwsN1uo7iGuFc2+AtlSr1G0QpCX7aVMql6SxB3jraieQTR2rN\n" +
            "p8BxmOM2qjLfOJ0CXRlDdW1RnKskadEQ7mvhOQnmKUkWEEztJRMDtOKTdXVeL9cg\n" +
            "r2cLtrT1/4ZSFuFeetYO6b/7vJRqhSIyp/pnH4piY5inWgbY+N+r+pIuVcDUqonb\n" +
            "ArJ8XH2lHG7T3ofjBGUrL2MYPjhnC4IdyefKfzEXABEBAAH+BwMCI+GOZOQIaAry\n" +
            "Ar3gPMK8hPGVX6QzQNs9VYb4+n6QXViSvg2GczCVgYUpZzVJYR9Iwq9sATY9lNRg\n" +
            "m+L+6BQVpAl02EHu1fSqu1q6W9pK2mJ2Vrx6CvL9ADfhavPKGVCfCWyoUxg7CO93\n" +
            "u+1n3b0M+ZwLTarQEbWiNKlwJFPUUw0qa1dq0y/4NrVGerVnlHLViHEmESPK9FZO\n" +
            "K9I9napiiO+Ld2d/kbxnkPW1qdFcUuiWRF1gNByRRbU2d8QFBBCwulozgn6dks/U\n" +
            "ElbPckOX72e5ngEs0yOHTNvQ4EqnMsKgxpVQYBAya4PNbCuCEXjNcpciMDf8ci3w\n" +
            "QgCOfAIlq4n4OESkTjGlx+0qAYcAG6HsjhpkHFzQmX7BCXiH6B7Hsv/jFUg0QCXU\n" +
            "3vMBwLrWegfh4XphTFy1NWQvs4tA2OIkfxQZreWm2TKjky9uP5esSOOS7BtkDHHx\n" +
            "xTpcfSpoIgYwXmjaiGg4d2usvEUeD7XhfslDH1z+wvFUrKNOezvLh2PnejKmB0tr\n" +
            "Xh3bGFun1hWLaH2khSWqI3rrSWj2Qu3nRFTKQKl/i+1mUGeunokO0x7YjiXyDvOI\n" +
            "YmwH3zZla5t03V+GyQXI/SARg6py5AsCE8UHUlUfpKCio6vJSvJy/i9MkgRuHnD7\n" +
            "FGos6DYMlYJypYwbfVvNevgUtS594lQGux6F7Ubsfoj1/BwNs0cJAj9HFFTI/OaA\n" +
            "bgIRuVT2Orpu4NUwbXAlciv1OtDUa9z7hevOqr7ZGLjZYZYzujv6LQ/sqlLS8FEy\n" +
            "1Ho0l8D0EeDNFMbH6ffJTfYo4VXc25AMpBm3ny/e15xVc87MfKNi5Ucgnw08egJu\n" +
            "fpRqTjH4HEJdyWeURa0z8BzKNdlDJxOOaOyfthoUuYdY+QobPzj2okMuyJfFXS0Q\n" +
            "PbJCKK+GLX7Hsv3StkFI2U3AZ4zkAR45m0JhPAeZy9nY4/nxuAVcIPJMWQMom3WN\n" +
            "fLfN5tWfpr8vNL9uUFaop/oizoOXZ92QiZI8MInF6B1gSKxO5DLzszY1ZVbLVog0\n" +
            "fScLV8Y4Zh29fO3UgD22Xz6XIdKzWw8hULAIGvNEHQdsy43Iw0Ohw3l8uPtKiyZc\n" +
            "VjffFALDCwYHaw/Fx1rmokD9GWmtuztSJX+DByBpH6NOc8bSziQX7vC5AuKSE20b\n" +
            "EpQeXqWf8aI/r7IEjLRUak5IEkmjF/47R2tz5pv6oYxOfb6PGfA3AI53kfxsjlS3\n" +
            "sZAUxakg8P/jwteD/pW2XU7xly1+sC4HTDOuLTuvPgeXy/rGqPscp7o/RmZyaBqm\n" +
            "Lh8IXFMPEH2K8xoBLcJoCWLTZi3ouVfLa0ImLlh8320uuSIQ1R+H8OU+556JAbwE\n" +
            "GAECACYWIQQlALqWsWZjEbY6ce7MOGmHGx6QOwUCYl4DPQIbDAUJA8JnAAAKCRDM\n" +
            "OGmHGx6QOy+MC/9LzR40fgnRFqLbt/dv5TmRSzwV6r98xpbiuscScaUVWFWlh5Zx\n" +
            "Xac9eWwhEXAzYFwtldz6wuHI2VBBr/x96wQBcIyzGa6kp93xzEPvfb6zgdCCBhNM\n" +
            "14JsPvyUAcatQhw8YkHhIODVQDIJNVsZqEg0EcBj2PDYKe7kbVHT1n4YsjQzxUwp\n" +
            "ItUBk7uPX9Y5dMUqimX1D63chRF0Z3O64XHZ6BFuqAhZ75XYB+hI5TJjCn0ymNku\n" +
            "QG6NFtQim5Eakz1FznUskEccyBxGMRaUrLOqilQtEtULcGyxuhmWzx1RcYNVojqw\n" +
            "YwwHQaNQ6PM8zzeWqe/S+8JHIMEz1WXVwY/p9K6qxCL0sgmcGdEZAhIeiYpn2OZt\n" +
            "m3TWVDdJ0Xfv0t6giDhBWp98k/Ta49w+01Jn72c92rCLLlMqV/Hklv8uNuVKQuAl\n" +
            "u5CZ5TuBY3Si5lu65bRx/UXTDmJaXYlpLHg63CuCHCKYrmd7D6TvycvcdA9UDtb/\n" +
            "sRK+VeFezQN3qAg=\n" +
            "=7qQZ\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private static final Passphrase passphrase = Passphrase.fromPassword("Arity2022");

    @Test
    public void testDecryption() throws IOException, PGPException {
        // Set a signature hash algorithm that accepts SHA1
        PGPainless.getPolicy().setSignatureHashAlgorithmPolicy(
                new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512, Arrays.asList(
                        HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256, HashAlgorithm.SHA224, HashAlgorithm.SHA1, HashAlgorithm.RIPEMD160
                )));

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(passphrase);
        InputStream cipherText = GnuPGInteropTest.class.getClassLoader().getResourceAsStream("launch-docker.sh.gpg");

        // Decrypt
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cipherText)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKeys, protector));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
        assertTrue(metadata.isEncrypted());

        System.out.println(out);
    }
}
