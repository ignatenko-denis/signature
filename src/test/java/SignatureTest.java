import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignatureTest {
    private static final String KEY_PAIR_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String DATA_FILE = "src/test/resources/data.txt";
    private static final String PRIVATE_KEY_FILE = "src/test/resources/private_key.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/public_key.pem";

    @Test
    public void signature() throws Exception {
        byte[] data = Files.readAllBytes(Path.of(DATA_FILE));

        // Creating KeyPair generator object with RSA algorithm
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_ALGORITHM);

        // Initializing the key pair generator
        keyPairGenerator.initialize(2048);

        // Generate the pair of keys
        KeyPair pair = keyPairGenerator.generateKeyPair();

        // save private key in PEM-file
        try (var writer = new JcaPEMWriter(new PrintWriter(PRIVATE_KEY_FILE))) {
            writer.writeObject(pair.getPrivate());
        }

        // save public key in PEM-file
        try (var writer = new JcaPEMWriter(new PrintWriter(PUBLIC_KEY_FILE))) {
            writer.writeObject(pair.getPublic());
        }

        // Getting the private key from the PEM-file
        PrivateKey privateKey = readPrivateKey(new File(PRIVATE_KEY_FILE));

        // Creating a Signature object
        Signature signatureCreator = Signature.getInstance(SIGNATURE_ALGORITHM);

        // Initializing the signature
        signatureCreator.initSign(privateKey);

        // Adding data to the signature
        signatureCreator.update(data);

        // Calculating the signature
        byte[] signature = signatureCreator.sign();

        // Creating a Signature object for validation
        Signature signatureValidator = Signature.getInstance(SIGNATURE_ALGORITHM);

        // Getting the public key from the PEM-file
        PublicKey publicKey = readPublicKey(new File(PUBLIC_KEY_FILE));

        // Initializing the signature
        signatureValidator.initVerify(publicKey);
        signatureValidator.update(data);

        // Verifying the signature
        assertTrue(signatureValidator.verify(signature));
    }

    private PrivateKey readPrivateKey(File file) throws Exception {
        try (var pemParser = new PEMParser(new FileReader(file))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            Object pemObject = pemParser.readObject();
            KeyPair keyPair = converter.getKeyPair((PEMKeyPair) pemObject);
            return keyPair.getPrivate();
        }
    }

    private PublicKey readPublicKey(File file) throws Exception {
        var factory = KeyFactory.getInstance(KEY_PAIR_ALGORITHM);

        try (var pemReader = new PemReader(new FileReader(file))) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);
            return factory.generatePublic(keySpec);
        }
    }
}
