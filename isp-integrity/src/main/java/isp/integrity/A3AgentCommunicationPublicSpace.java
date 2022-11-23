package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        final Key key_alice_public = KeyGenerator.getInstance("ChaCha20").generateKey();

        // Create an AES key that is used by Bob and the public-space
        final Key key_bob_public = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);
                // Random is way faster for "testing"
//                new Random().nextBytes(data);


                // Alice sends the data directly to Bob
                // The channel between Alice and Bob is not secured
                send("bob", data);

                // Alice then computes the digest of the data and sends the digest to public-space

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digest = digestAlgorithm.digest(data);
                print("Message digest: %s", hex(digest));
                print("Message : %s", hex(Arrays.copyOf(data, 10)));

                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.

                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                byte[] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                IvParameterSpec iv = new IvParameterSpec(nonce);
                cipher.init(Cipher.ENCRYPT_MODE, key_alice_public, iv);
                byte[] encrypted_digest = cipher.doFinal(digest);
                send("public-space", nonce);
                send("public-space", encrypted_digest);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                final byte[] nonce = receive("alice");
                final byte[] data = receive("alice");

                Cipher cipher_alice = Cipher.getInstance("ChaCha20-Poly1305");
                IvParameterSpec iv_alice = new IvParameterSpec(nonce);
                cipher_alice.init(Cipher.DECRYPT_MODE, key_alice_public, iv_alice);
                byte[] digest = cipher_alice.doFinal(data);
                print("Message digest: %s", hex(digest));

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final Cipher cipher_bob = Cipher.getInstance("AES/GCM/NoPadding");
                cipher_bob.init(Cipher.ENCRYPT_MODE, key_bob_public);
                final byte[] iv_bob = cipher_bob.getIV();
                send("bob", iv_bob);
                final byte[] encrypted_digest = cipher_bob.doFinal(digest);
                send("bob", encrypted_digest);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                final byte[] data_received = receive("alice");
                final byte[] data = Arrays.copyOf(data_received, data_received.length);
//                data[0] = 69;

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digest_computed = digestAlgorithm.digest(data);
                print("Message digest computed: %s", hex(digest_computed));
                print("Message : %s", hex(Arrays.copyOf(data, 10)));
                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space

                final byte[] iv = receive("public-space");
                final byte[] encrypted_digest = receive("public-space");

                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, key_bob_public, specs);
                final byte[] digest = cipher.doFinal(encrypted_digest);
                print("Message digest: %s", hex(digest));

                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                if(MessageDigest.isEqual(digest_computed, digest)) {
                    print("data valid");
                }else{
                    print("data invalid");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
