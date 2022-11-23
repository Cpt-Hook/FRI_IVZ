package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class ActiveMITM {
    public static void main(String[] args) throws Exception {
        // David and FMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "prf.denis@fri.si\n" +
                        "david@fri.si\n" +
                        "Some ideas for the exam\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));
                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                final String newEmail =      "isp@gmail.com   ";
                final String originalEmail = "prf.denis@fri.si";
                final byte[] newEmailBytes = newEmail.getBytes(StandardCharsets.UTF_8);
                final byte[] originalEmailBytes = originalEmail.getBytes(StandardCharsets.UTF_8);
                assert newEmailBytes.length == originalEmailBytes.length;

                final byte[] bytes = receive("david");
                byte[] iv = receive("david");
                print(" IN: %s", hex(bytes));

                // As the person-in-the-middle, modify the ciphertext
                // so that the FMTP server will send the email to you
                // (Needless to say, you are not allowed to use the key
                // that is being used by david and server.)

                for (int i = 0; i < newEmailBytes.length; i++) {
                    iv[i] ^= newEmailBytes[i] ^ originalEmailBytes[i];
                }

                print("OUT: %s", hex(bytes));
                send("server", bytes);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");
        env.start();
    }
}
