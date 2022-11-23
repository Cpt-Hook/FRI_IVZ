package isp.secrecy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {

    /**
     * Inspired by <a href="https://stackoverflow.com/questions/2183240/java-integer-to-byte-array">...</a>
     */
    static void IntToByteArray(int data, byte[] result) {
        result[3] = (byte) ((data & 0xFF000000) >> 24);
        result[2] = (byte) ((data & 0x00FF0000) >> 16);
        result[1] = (byte) ((data & 0x0000FF00) >> 8);
        result[0] = (byte) ((data & 0x000000FF));
    }

    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // set random key
        byte[] keyBytes = {32, 126, 2, 0, 0, 0, 0, 0};
        final Key key = new SecretKeySpec(keyBytes, "DES");
        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);

        final byte[] ct = encrypt.doFinal(message.getBytes());
        final byte[] bruteforcedKey = bruteForceKey(ct, message);

        System.out.println("Key correct: " + Arrays.equals(bruteforcedKey, keyBytes));
        for (byte keyByte : keyBytes) {
            System.out.print(keyByte + ", ");
        }
        System.out.println();
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        byte[] keyBytes = {0, 0, 0, 0, 0, 0, 0, 0};

        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // loop over 2^24 possible keys
        for (int possibleKey = 0; possibleKey < (int)Math.pow(2, 8*3); possibleKey++) {
            // set key bytes according to the possibleKey
            IntToByteArray(possibleKey, keyBytes);

            final Key key = new SecretKeySpec(keyBytes, "DES");
            encrypt.init(Cipher.DECRYPT_MODE, key);

            // try decrypting and compare with plaintext
            try {
                String pt = new String(encrypt.doFinal(ct));
                if (pt.equals(message)) {
                    return keyBytes;
                }
            }
            catch(BadPaddingException ignored) {}
        }

        return null;
    }
}
