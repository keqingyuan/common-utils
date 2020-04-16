package cc.kebei.commons.crypto.digest;

import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class HashHelperTest {

    @Test
    public void digest() {
        String data = "你好我叫柯北";
        try {
            byte[] bytes1 = HashHelper.MD5.digest(data.getBytes());
            System.out.println(new String(bytes1));
            byte[] bytes2 = HashHelper.SHA1.digest(data.getBytes());
            System.out.println(new String(bytes2));
            byte[] bytes3 = HashHelper.SHA224.digest(data.getBytes());
            System.out.println(new String(bytes3));
            byte[] bytes4 = HashHelper.SHA256.digest(data.getBytes());
            System.out.println(new String(bytes4));
            byte[] bytes5 = HashHelper.SHA512.digest(data.getBytes());
            System.out.println(new String(bytes5));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void digestToBase64() {
        String data = "你好我叫柯北";
        try {
            String bytes1 = HashHelper.MD5.digestToBase64(data.getBytes());
            System.out.println(new String(bytes1));
            String bytes2 = HashHelper.SHA1.digestToBase64(data.getBytes());
            System.out.println(new String(bytes2));
            String  bytes3 = HashHelper.SHA224.digestToBase64(data.getBytes());
            System.out.println(new String(bytes3));
            String bytes4 = HashHelper.SHA256.digestToBase64(data.getBytes());
            System.out.println(new String(bytes4));
            String  bytes5 = HashHelper.SHA512.digestToBase64(data.getBytes());
            System.out.println(new String(bytes5));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void digestToHex() {
        String data = "你好我叫柯北";
        try {
            String bytes1 = HashHelper.MD5.digestToHex(data.getBytes());
            System.out.println(new String(bytes1));
            String bytes2 = HashHelper.SHA1.digestToHex(data.getBytes());
            System.out.println(new String(bytes2));
            String  bytes3 = HashHelper.SHA224.digestToHex(data.getBytes());
            System.out.println(new String(bytes3));
            String bytes4 = HashHelper.SHA256.digestToHex(data.getBytes());
            System.out.println(new String(bytes4));
            String  bytes5 = HashHelper.SHA512.digestToHex(data.getBytes());
            System.out.println(new String(bytes5));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}