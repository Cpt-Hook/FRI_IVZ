package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

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
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
                final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, key);
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
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */

                // receive IV first
                final byte[] iv = receive("alice");

                final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
                decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));


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
