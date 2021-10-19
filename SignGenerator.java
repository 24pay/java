package eu.pay24.common;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;

@Service
public class SignGenerator {

    private SecureRandom r = new SecureRandom();
    private Cipher c;
    private IvParameterSpec IV;
    private SecretKey s_KEY;

    @Value("${paygate.mid}")
    private String mid;

    @Value("${paygate.key}")
    private String key;

    public String sign(String signText) throws Exception{
        return CryptoUtils.bytesToHex(this.generateSign(sha1bytes(signText))).substring(0, 32).toUpperCase();
    }

    public byte[] generateSign(byte[] byteToEncrypt)throws Exception{

        // INIT
        String iv = mid + new StringBuffer(mid).reverse().toString();

        this.c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        this.IV = new IvParameterSpec(iv.getBytes());

        int len = key.length();
        byte[] keybytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            keybytes[i / 2] = (byte) ((Character.digit(key.charAt(i), 16) << 4)
                    + Character.digit(key.charAt(i+1), 16));
        }
        this.s_KEY = new SecretKeySpec(keybytes,"AES");
		
        // EXECUTION
        this.c.init(Cipher.ENCRYPT_MODE, this.s_KEY, this.IV, this.r);
        return this.c.doFinal(byteToEncrypt);
    }

    public byte[] sha1bytes(String message) {

        try{
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return md.digest(message.getBytes("UTF-8"));
        }
        catch (Exception ex){
            // Could not create SHA1 hash from message
        }
        return null;
    }
}
