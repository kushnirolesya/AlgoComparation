import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Random;

public class CryptoUtils {

    public static String generateRandomString(int length) {
        int leftLimit = 47;
        int rightLimit = 122;
        Random random = new Random();

        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(length)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    public static IvParameterSpec getIVSecureRandom(String algo) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[Cipher.getInstance(algo).getBlockSize()];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}

