import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;

public class RSAUtil {


    public static PrivateKey getRSAPrivateKey(String pkcs8_rsa_private_key) {
        byte[] keyBytes = pkcs8_rsa_private_key.getBytes();

        String pem = new String(keyBytes);
        pem = pem.replace("-----BEGIN rsa private key-----", "");
        pem = pem.replace("-----END rsa private key-----", "");
        pem = pem.replace("\n", "");

        byte[] decoded = Base64.decodeBase64(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        PrivateKey privateKey = null;

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(spec);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static PublicKey getRSAPublicKey(String pkcs8_rsa_public_key) {
        byte[] keyBytes = pkcs8_rsa_public_key.getBytes();

        String pem = new String(keyBytes);
        pem = pem.replace("-----BEGIN rsa public key-----", "");
        pem = pem.replace("-----END rsa public key-----", "");
        pem = pem.replace("\n", "");
        byte[] decoded = Base64.decodeBase64(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        PublicKey publicKey = null;

        try {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(spec);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return publicKey;
    }
//    /**
//     * 公钥加密（B用A的公钥加密）
//     * @param plainText
//     * @param pkcs8_rsa_public_key
//     * @return
//     */
//    public static String doEncryptByRSA(String plainText) {
//        byte[] sourceData = plainText.getBytes();
//        String result = null;
//
//        try {
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//            byte[] resultData = cipher.doFinal(sourceData);
//            result = Base64.encodeBase64String(resultData);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return result;
//    }
//    /**
//     * 私钥解密（A使用私钥解密）
//     * @param encryptedText
//     * @param pkcs8_rsa_private_key
//     * @return
//     */
//    public static String doDecryptByRSA(String encryptedText) {
//        byte[] sourceData = Base64.decodeBase64(encryptedText);
//        String result = null;
//
//        try {
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, privateKey);
//            byte[] resultData = cipher.doFinal(sourceData);
//            result = new String(resultData);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        return result;
//    }
}