package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        final int message_count = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                final Mac mac = Mac.getInstance("HmacSHA256");
                for (int i = 0; i < message_count; i++) {
                    final String text = String.format("I hope you get this message number %d intact. Kisses, Alice.", i);
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    mac.init(key);
                    final byte[] pt_digest = mac.doFinal(pt);

                    send("bob", pt);
                    send("bob", pt_digest);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for (int i = 0; i < message_count; i++) {
                    final byte[] pt = receive("alice");
                    final byte[] pt_digest = receive("alice");

                    print("[Message]: %s", new String(pt));
                    print("[Received HMAC]:   %s", hex(pt_digest));

                    final Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(key);
                    final byte[] pt_digest_mine = mac.doFinal(pt);

                    print("[Calculated HMAC]: %s", hex(pt_digest_mine));

                    // timing-attack safe comparison
                    if (!MessageDigest.isEqual(pt_digest_mine, pt_digest)) {
                        throw new AEADBadTagException("HMAC mismatch");
                    }

                    print("%s\n", "The integrity check was successful");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
