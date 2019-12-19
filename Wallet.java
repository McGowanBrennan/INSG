import java.security.*;
import java.io.*;
import java.nio.file.*;
import java.security.spec.*;
import java.util.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.nio.charset.StandardCharsets;



import javax.crypto.Cipher;

public class Wallet{
    PublicKey publicKey;
    PrivateKey privateKey;
    String fileName;
    String caseID;
    public ArrayList<Wallet> wallets = new ArrayList<>();

    Wallet(PublicKey publicKey, PrivateKey privateKey, String fileName){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.fileName = fileName;
        this.caseID = caseID;

    }
    static KeyPair LoadKeyPair(String filename) throws Exception {
        // Read wallet
        Scanner sin = new Scanner(new File(filename));
        byte[] encodedPublicKey = getByteArray(sin.next());
        byte[] encodedPrivateKey = getByteArray(sin.next());
        sin.close();
        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return new KeyPair(publicKey, privateKey);
    }
    static byte[] getByteArray(String hexstring) {
        byte[] ret = new byte[hexstring.length()/2];
        for (int i = 0; i < hexstring.length(); i += 2) {
            String hex = hexstring.substring(i,i+2);
            if ( hex.equals("") )
                continue;
            ret[i/2] = (byte) Integer.parseInt(hex,16);
        }
        return ret;
    }
    static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            int val = b[i];
            if ( val < 0 )
                val += 256;
            if ( val <= 0xf )
                result += "0";
            result += Integer.toString(val, 16);
        }
        return result;
    }

    void addToList(Wallet wallet){
        wallets.add(wallet);
    }
    //https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java





    public static void main(String[] args){}
}

