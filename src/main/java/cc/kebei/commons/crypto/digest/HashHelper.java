package cc.kebei.commons.crypto.digest;

import cc.kebei.commons.crypto.SecurityProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.annotation.concurrent.NotThreadSafe;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author Ke Bei
 * @date 2020-1-10
 */
@NotThreadSafe
public class HashHelper {

    public static final HashHelper MD5 = new HashHelper("MD5");

    public static final HashHelper SHA1 = new HashHelper("SHA1");

    public static final HashHelper SHA224 = new HashHelper("SHA224");

    public static final HashHelper SHA256 = new HashHelper("SHA256");

    public static final HashHelper SHA512 = new HashHelper("SHA512");

    private String algorithm;

    public HashHelper(String algorithm) {
        super();
        this.algorithm = algorithm;
    }

    private HashHelper() {

    }
    /**
     * digest
     * @param data
     * @return byte array
     * @throws NoSuchAlgorithmException
     */
    public byte[] digest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm, SecurityProvider.BCProvider());
        messageDigest.update(data);
        return messageDigest.digest();
    }

    /**
     * digest
     * @param data
     * @return Base64 String
     * @throws NoSuchAlgorithmException
     */
    public String digestToBase64(byte[] data) throws NoSuchAlgorithmException {
        byte[] buf = digest(data);
        return Base64.toBase64String(buf);
    }

    /**
     * digest
     * @param data
     * @return Hex String
     * @throws NoSuchAlgorithmException
     */
    public String digestToHex(byte[] data) throws NoSuchAlgorithmException {
        byte[] buf = digest(data);
        return Hex.toHexString(buf);
    }

}
