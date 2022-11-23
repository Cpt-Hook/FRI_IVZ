package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();
        final int messageCount = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */
                final Cipher encrypt = Cipher.getInstance("ChaCha20");
                byte[] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1));
                final byte[] iv = encrypt.getIV();

                // send IV first
                send("bob", iv);

                // send the 10 messages
                for (int i = 0; i < messageCount; i++) {
                    final String message = String.format("Message number %d.", i+1);
                    final byte[] pt = message.getBytes();
                    final byte[] ct = (i == messageCount-1)? encrypt.doFinal(pt) : encrypt.update(pt);
                    System.out.println("[ALICE]\t" + "Sending CT: " + hex(ct));
                    send("bob", ct);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // receive IV first (iv is the nonce for ChaCha20)
                final byte[] iv = receive("alice");

                final Cipher decrypt = Cipher.getInstance("ChaCha20");
                decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(iv, 1));

                for (int i = 0; i < messageCount; i++) {
                    final byte[] ct = receive("alice");
                    final byte[] dt = (i == messageCount-1)? decrypt.doFinal(ct) : decrypt.update(ct);
                    System.out.println("[BOB]\t" + new String(dt));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
