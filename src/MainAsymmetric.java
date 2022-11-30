import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

public class MainAsymmetric {
    static long startTime;
    static long endTime;
    static String encryptedString;
    static String decryptedString;
    static String publicKey;
    static String privateKey;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
            ElGamalKeyPairGenerator keyPairGeneratorElGamal = new ElGamalKeyPairGenerator();

            publicKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
            privateKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded());

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(50), publicKey));
                decryptedString = RSA.decrypt(encryptedString, privateKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 ���������� | 50  ���� | RSA | " + ((endTime - startTime) / 1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(100), publicKey));
                decryptedString = RSA.decrypt(encryptedString, privateKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 ���������� | 100 ���� | RSA | " + ((endTime - startTime) / 1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(117), publicKey));
                decryptedString = RSA.decrypt(encryptedString, privateKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 ���������� | 117 ���� | RSA | " + ((endTime - startTime) / 1000.0F) + " ������");

            publicKey = Base64.getEncoder().encodeToString(keyPairGeneratorElGamal.getPublicKey().getEncoded());
            privateKey = Base64.getEncoder().encodeToString(keyPairGeneratorElGamal.getPrivateKey().getEncoded());

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(50), publicKey));
                decryptedString = ElGamal.decrypt(encryptedString, privateKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 ���������� | 50  ���� | ElG | " + ((endTime - startTime) / 1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(100), publicKey));
                decryptedString = ElGamal.decrypt(encryptedString, privateKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 ���������� | 100 ���� | ElG | " + ((endTime - startTime) / 1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(117), publicKey));
                decryptedString = ElGamal.decrypt(encryptedString, privateKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 ���������� | 117 ���� | ElG | " + ((endTime - startTime) / 1000.0F) + " ������");

        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }
    }
}
