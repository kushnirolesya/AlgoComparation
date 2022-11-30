import java.security.*;

public class ElGamalKeyPairGenerator {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public ElGamalKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }
}
