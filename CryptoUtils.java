package shshsb.sbssbab;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    /**
     * ChaCha20 فك تشفير مع تخطي أول 64 بايت (seek(64))
     */
    public static byte[] chacha20Decrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        try {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            engine.init(false, new ParametersWithIV(new KeyParameter(key), nonce));

            // skip first 64 bytes of keystream
            byte[] skip = new byte[64];
            engine.processBytes(skip, 0, 64, skip, 0);

            byte[] out = new byte[ciphertext.length];
            engine.processBytes(ciphertext, 0, ciphertext.length, out, 0);
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * AES/ECB/PKCS5Padding فك تشفير
     */
    public static byte[] aesEcbDecrypt(byte[] key, byte[] ciphertext) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(ciphertext);
        } catch (Exception e) {
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    public static boolean startsWith(byte[] arr, byte[] prefix) {
        if (arr.length < prefix.length) return false;
        return Arrays.equals(Arrays.copyOf(arr, prefix.length), prefix);
    }
}