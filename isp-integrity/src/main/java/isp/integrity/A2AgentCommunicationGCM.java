package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        final int message_count = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");


                for (int i = 0; i < message_count; i++) {
                    // send IV
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] iv = cipher.getIV();
                    send("bob", iv);
                    System.out.printf("IV:  %s%n", Agent.hex(iv));

                    final String text = String.format("I hope you get this message number %d intact and in secret. Kisses, Alice.", i);
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final byte[] ct = cipher.doFinal(pt);
                    send("bob", ct);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                for (int i = 0; i < message_count; i++) {
                    final byte[] iv = receive("alice");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, specs);

                    final byte[] ct = receive("alice");
                    final byte[] pt = cipher.doFinal(ct);

                    System.out.printf("PT:  %s%n", Agent.hex(pt));
                    System.out.printf("MSG: %s%n", new String(pt, StandardCharsets.UTF_8));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
