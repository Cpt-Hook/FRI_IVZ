package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using an
 * RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the isp.steganography.ImageSteganography
 * class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final String algorithm = "RSA/ECB/OAEPPadding";

        // Create two public-secret key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();
        final KeyPair aliceKP = kpg.generateKeyPair();

        final int message_count = 10;

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final Cipher rsa = Cipher.getInstance(algorithm);

                for (int i = 0; i < message_count; i++) {
                    // send part
                    String message = String.format("Alice calls bob number %d!", i);
                    rsa.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                    final byte[] ct_send = rsa.doFinal(message.getBytes());
                    send("bob", ct_send);
                    System.out.println("[alice] CT: " + Agent.hex(ct_send));

                    // receive part
                    rsa.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] ct = receive("bob");
                    final byte[] decryptedText = rsa.doFinal(ct);
                    System.out.println("[alice] PT: " + new String(decryptedText));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Cipher rsa = Cipher.getInstance(algorithm);
                rsa.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());

                for (int i = 0; i < message_count; i++) {
                    // send part
                    rsa.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());
                    String message = String.format("Bob calls alice number %d!", i);
                    final byte[] ct_send = rsa.doFinal(message.getBytes());
                    send("alice", ct_send);
                    System.out.println("[bob] CT: " + Agent.hex(ct_send));

                    // receive part
                    rsa.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] ct = receive("alice");
                    final byte[] decryptedText = rsa.doFinal(ct);
                    System.out.println("[bob] PT: " + new String(decryptedText));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
