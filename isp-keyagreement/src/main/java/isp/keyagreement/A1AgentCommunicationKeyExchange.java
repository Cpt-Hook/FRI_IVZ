package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final String algorithm = "RSA/ECB/OAEPPadding";
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "this is my message from alice to bob";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                // key exchange using RSA
                final KeyGenerator kg = KeyGenerator.getInstance("AES");
                final SecretKey symKey = kg.generateKey();
                print("Generated key bytes: %s", hex(symKey.getEncoded()));


                final byte[] pubKeyEncoded = receive("bob");
                PublicKey publicKey =
                        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyEncoded));
                final Cipher rsaEnc = Cipher.getInstance(algorithm);
                rsaEnc.init(Cipher.ENCRYPT_MODE, publicKey);
                final byte[] symKeyCT = rsaEnc.doFinal(symKey.getEncoded());
                send("bob", symKeyCT);

                // AESGCM encryption
                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                alice.init(Cipher.ENCRYPT_MODE, symKey);
                final byte[] ct = alice.doFinal(pt);
                send("bob", alice.getIV());
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // key exchange using RSA
                send("alice", bobKP.getPublic().getEncoded());
                final byte[] symKeyCT = receive("alice");

                final Cipher rsaDec = Cipher.getInstance(algorithm);
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] symKeyBytes = rsaDec.doFinal(symKeyCT);
                SecretKey symKey = new SecretKeySpec(symKeyBytes, "AES");
                print("Received key bytes: %s", hex(symKey.getEncoded()));

                // AESGCM encryption
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                bob.init(Cipher.DECRYPT_MODE, symKey, specs);
                final byte[] pt = bob.doFinal(ct);
                print("Decrypted message: %s", new String(pt));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}