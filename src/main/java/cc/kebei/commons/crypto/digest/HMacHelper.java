package cc.kebei.commons.crypto.digest;

import cc.kebei.commons.crypto.SecurityProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Ke Bei
 * @date 2020-1-12
 */
@NotThreadSafe
public class HMacHelper {

    public static final HMacHelper HmacMD5 = new HMacHelper("HmacMD5");
    public static final HMacHelper HmacSHA1 = new HMacHelper("HmacSHA1");
    public static final HMacHelper HmacSHA224 = new HMacHelper("HmacSHA224");
    public static final HMacHelper HmacSHA256 = new HMacHelper("HmacSHA256");
    public static final HMacHelper HmacSHA384 = new HMacHelper("HmacSHA384");
    public static final HMacHelper HmacSHA512 = new HMacHelper("HmacSHA512");

    private String algorithm;

    public HMacHelper(String algorithm) {
        super();
        this.algorithm = algorithm;
    }

    private HMacHelper(){

    }

    /**
     * digest
     * @param data data
     * @param key key
     * @return byte array
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public byte[] digest(byte[] data, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm, SecurityProvider.BCProvider());
        mac.init(key);
        return mac.doFinal(data);
    }

    /**
     * Base64 Digest
     * @param data data
     * @param key key
     * @return Base64
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public String digestToBase64(byte[] data, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] buf = digest(data,key);
        return Base64.toBase64String(buf);
    }

    /**
     * Hex Digest
     * @param data data
     * @param key key
     * @return Hex
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public String digestToHex(byte[] data, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] buf = digest(data,key);
        return Hex.toHexString(buf);
    }
}
