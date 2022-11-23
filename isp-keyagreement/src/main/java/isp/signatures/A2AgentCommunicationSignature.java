package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final Environment env = new Environment();

        // Create key pairs
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keyPairAlice = g.generateKeyPair();
        KeyPair keyPairBob = g.generateKeyPair();

        final int numberOfMessages = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times
                Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
                Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
                for (int i = 0; i < numberOfMessages; i++) {
                    // sign and send
                    String message = String.format("Message from alice to bob %d", i);
                    byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

                    ecdsaSign.initSign(keyPairAlice.getPrivate());
                    ecdsaSign.update(plaintext);
                    byte[] signature = ecdsaSign.sign();
                    send("bob", plaintext);
                    send("bob", signature);

                    // receive and verify
                    plaintext = receive("bob");
                    signature = receive("bob");
                    ecdsaVerify.initVerify(keyPairBob.getPublic());
                    ecdsaVerify.update(plaintext);
                    boolean result = ecdsaVerify.verify(signature);
                    print(new String(plaintext, StandardCharsets.UTF_8) + " signature result: " + result);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
                Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");

                for (int i = 0; i < numberOfMessages; i++) {
                    // receive and verify
                    byte[] plaintext = receive("alice");
                    byte[] signature = receive("alice");
                    ecdsaVerify.initVerify(keyPairAlice.getPublic());
                    ecdsaVerify.update(plaintext);
                    boolean result = ecdsaVerify.verify(signature);
                    print(new String(plaintext, StandardCharsets.UTF_8) + " signature result: " + result);

                    // sign and send
                    String message = String.format("Message from bob to alice %d", i);
                    plaintext = message.getBytes(StandardCharsets.UTF_8);

                    ecdsaSign.initSign(keyPairBob.getPrivate());
                    ecdsaSign.update(plaintext);
                    signature = ecdsaSign.sign();
                    send("alice", plaintext);
                    send("alice", signature);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}