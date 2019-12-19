import java.nio.charset.StandardCharsets;
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

import javax.crypto.Cipher;


public class INSG{

    public HashMap<String, Integer> sent = new HashMap<String, Integer>();
    public HashMap<String, Integer> received = new HashMap<>();
    int blockCount = 1;

    public static KeyPair buildKeyPair(){
        try {
            final int keySize = 2048;
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    // this converts an array of bytes into a hexadecimal number in
    // text format
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

    // this converts a hexadecimal number in text format into an array
    // of bytes
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

    // This will write the public/private key pair to a file in text
    // format.  It is adapted from the code from
    // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
    static void SaveKeyPair(String filename, KeyPair keyPair) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        PrintWriter fout = new PrintWriter(new FileOutputStream(filename));
        fout.println(getHexString(x509EncodedKeySpec.getEncoded()));
        fout.println(getHexString(pkcs8EncodedKeySpec.getEncoded()));
        fout.close();
    }

    // This will read a public/private key pair from a file.  It is
    // adapted from the code from
    // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
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

    // This will get the SHA-256 hash of a file, and is the same as
    // calling the `sha256sum` command line program
    static String getSignatureOfFile(String filename) throws Exception {
        byte[] filebytes = Files.readAllBytes(Paths.get(filename));
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(filebytes);
        return getHexString(encodedHash);
    }

    void genesis(){
        String filename = "block_0.txt";
        PrintWriter fout = null;
        try {
            fout = new PrintWriter(new FileOutputStream(filename));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        fout.println("This coin serves no purpose rather than to hopefully get a decent grade on a homework assignment.");
        fout.close();
        String ledger = "ledger.txt";
        try {
            fout = new PrintWriter(new FileOutputStream(ledger));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }

    void fund(String address, int amount, String fileName){
        int x = 0;
        received.put(address, amount);
        Date date = new Date();
        System.out.println("Funded wallet " + address + " with " + amount + " INSG " + "on " + date.toString() );
        PrintWriter fout = null;
        try {
            fout = new PrintWriter(new FileOutputStream(fileName));
        } catch (FileNotFoundException e) {
        }
        fout.println("Funded wallet " + address + " with " + amount + " INSG " + "on " + date.toString() );
        fout.close();
    }

    Wallet generate(String walletName){
        KeyPair keyPair = buildKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        Wallet newWallet = new Wallet(pubKey,privateKey,walletName);
        String filename = walletName;
        newWallet.addToList(newWallet);
        //PrintWriter fout = null;
        try {
            SaveKeyPair(filename, keyPair);
        }
        catch(Exception e){}
        System.out.println("New wallet generrated in " + walletName + " with signature " + address(filename));
        return newWallet;
    }

    void transfer(String walletName, String target, int amount, String fileName){
        Date date = new Date();
        String walletKey = address(walletName);
        received.put(target, amount);
        sent.put(walletKey, amount);

        System.out.println("Transferred " + amount + " from " + address(walletName) + " to " + target +
                " and processed at " + fileName + " on " + date.toString() );

        PrintWriter fout = null;
        try {
            fout = new PrintWriter(new FileOutputStream(fileName));
        } catch (FileNotFoundException e) {
        }
        fout.println(address(walletName));
        fout.println(target);
        fout.println(amount);
        fout.println(date.toString());
        KeyPair newKeys = null;
        try {
           KeyPair keys = LoadKeyPair(walletName);
           newKeys = keys;
        }
        catch(Exception e){}
        PrivateKey priv = newKeys.getPrivate();
        String toSign = address(walletName) + target + amount + date.toString();
        String signedMessage = "";
        try {
            String hash = sign(toSign, priv);
            signedMessage = hash;
        }
        catch(Exception e){}
        fout.println(signedMessage);
        fout.close();
    }


    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }
    int balance(String walletName) {
        int balance = 0;
        String compString = "";
        if(walletName.contains(".")){
            INSG test = new INSG();
            String hash = test.address(walletName);
            compString = hash;
        }
        else {compString = walletName;}
        for(Map.Entry wallet : received.entrySet())
        {
            //System.out.println("key: " + entry.getKey() + "; value: " + entry.getValue());
            if (walletName.equals(wallet.getKey())){
                //System.out.println(wallet);
                balance += Integer.parseInt(wallet.getValue().toString());
            }
        }
        for(Map.Entry wallet : sent.entrySet())
        {
            //System.out.println("key: " + wallet.getKey() + "; value: " + wallet.getValue());
            if (walletName.equals(wallet.getKey())){
                //System.out.println(wallet);
                balance -= Integer.parseInt(wallet.getValue().toString());
            }
        }

        return balance;
    }

    void verify(String targetWallet, String targetFile) throws Exception{
        System.out.println("Test");
        String key = address(targetWallet);
        File file = new File(targetFile);
        BufferedReader fileReader = new BufferedReader(new FileReader(file));
        String walletName = fileReader.readLine();
        String target = fileReader.readLine();
        String amount = fileReader.readLine();
        String date = fileReader.readLine();
        String signature = fileReader.readLine();

        KeyPair newKeys = null;
        try {
            KeyPair keys = LoadKeyPair(targetWallet);
            newKeys = keys;
        }
        catch(Exception e){}
        PrivateKey priv = newKeys.getPrivate();
        String toSign = address(targetWallet) + target + amount + date;
        String signedMessage = "";
        try {
            String hash = sign(toSign, priv);
            signedMessage = hash;
        }
        catch(Exception e){}
       // System.out.println(signature);
        //System.out.println(signedMessage);
        if(signature.equals(signedMessage)) {
            System.out.println("It works");

            PrintWriter pw = null;

            try {
                File ledger = new File("ledger.txt");
                FileWriter fw = new FileWriter(ledger, true);
                pw = new PrintWriter(fw);
                pw.println("Transferred " + amount + " from " + address(walletName) + " to " + target +" on " + date.toString() );
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (pw != null) {
                    pw.close();
                }
            }
        }

    }

    String address(String fileName){
        KeyPair keys = null;
        String signature = "";
        try {
            KeyPair newPair = LoadKeyPair(fileName);
            keys = newPair;
        }
        catch(Exception e){}
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
            String pubKeyHex = getHexString(x509EncodedKeySpec.getEncoded());
            //System.out.println(pubKeyHex);
            byte[] hash = digest.digest(pubKeyHex.getBytes(StandardCharsets.UTF_8));
            //https://howtodoinjava.com/array/convert-byte-array-string-vice-versa/
            String hashString = Base64.getEncoder().encodeToString(hash);
            signature = hashString.substring(0,16);
            //System.out.println(hashString.substring(0,16));
        }
        catch(Exception e){}
        return signature;
    }

    void mine(int difficulty) {

        ArrayList<String> linesToWrite = new ArrayList<>();
        ArrayList<String> linesOfPreviousBlock = new ArrayList<>();
        String targetFile = "ledger.txt";
        try {
            File file = new File(targetFile);
            BufferedReader fileReader = new BufferedReader(new FileReader(file));
            //https://stackoverflow.com/questions/5868369/how-to-read-a-large-text-file-line-by-line-using-java
            String line;
            try {
                while ((line = fileReader.readLine()) != null) {
                    linesToWrite.add(line);
                }
            } catch (Exception e) {
            }
            String hashThis = "";
            for (String transaction : linesToWrite) {
                hashThis += transaction;
            }


            String test = "8992";
            int count = 0;
            boolean condition = false;
            String finalString = "";
            int nonce = 0;
            while (condition != true) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                String pubkey = hashThis + count;
                //System.out.println(pubKeyHex);
                byte[] hash = digest.digest(pubkey.getBytes(StandardCharsets.UTF_8));
                //https://howtodoinjava.com/array/convert-byte-array-string-vice-versa/
                String hashString = Base64.getEncoder().encodeToString(hash);
                //System.out.println(hashString);
                count++;
                String testString = "";

                for (int i = 0; i < difficulty; i++) {
                    testString += "0";
                }
                if (hashString.substring(0, difficulty).equals(testString)) {
                    System.out.println("NONCE FOUND");
                    condition = true;
                    finalString = hashString;
                    nonce = count;
                }

            }


            PrintWriter pw = null;

            File newBlock = new File("block_" + blockCount + ".txt");

            try {
                int prevBlock = blockCount - 1;
                File file2 = new File("block_" + prevBlock + ".txt");
                String previousHash = "";
                if(prevBlock == 0){
                    BufferedReader fileReader3 = new BufferedReader(new FileReader(file2));
                    //https://stackoverflow.com/questions/5868369/how-to-read-a-large-text-file-line-by-line-using-java
                    String line3;
                    line3 = fileReader3.readLine();
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(line3.getBytes(StandardCharsets.UTF_8));
                    //https://howtodoinjava.com/array/convert-byte-array-string-vice-versa/
                    String hashString = Base64.getEncoder().encodeToString(hash);
                    previousHash = hashString;
                }
                else {
                    BufferedReader fileReader2 = new BufferedReader(new FileReader(file2));
                    //https://stackoverflow.com/questions/5868369/how-to-read-a-large-text-file-line-by-line-using-java
                    String line2;

                    try {
                        while ((line2 = fileReader2.readLine()) != null) {
                            linesOfPreviousBlock.add(line2);
                        }
                        String prevHash = "";
                        for (int i = 1; i < linesOfPreviousBlock.size(); i++) {
                            prevHash += linesOfPreviousBlock.get(i);

                        }
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(prevHash.getBytes(StandardCharsets.UTF_8));
                        //https://howtodoinjava.com/array/convert-byte-array-string-vice-versa/
                        String hashString = Base64.getEncoder().encodeToString(hash);
                        previousHash = hashString;

                    } catch (Exception e) {
                    }
                }


            try {
                File ledger = new File("block_" + blockCount + ".txt");
                FileWriter fw = new FileWriter(ledger, true);
                pw = new PrintWriter(fw);
                pw.println(previousHash);
                for (String add : linesToWrite) {
                    pw.println(add);
                }
                pw.println(nonce);
                //pw.println(finalString);
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (pw != null) {
                    pw.close();
                }

            }
            blockCount++;

        } catch (Exception e) {
        }
            try {
                PrintWriter writer = new PrintWriter("ledger.txt");
                writer.print("");
                writer.close();
            } catch (Exception e) {
            }

    }catch(Exception e){}}

    public static void main(String[] args){
        //System.out.println("Test");
        INSG wal = new INSG();
        wal.genesis();
        Wallet myWallet = wal.generate("Brennan.txt");
        Wallet bobWallet = wal.generate("Bob.txt");
        Wallet JerryWallet = wal.generate("Jerry.txt");
        String bobAddy = wal.address("Bob.txt");
        String jerrdyAddy = wal.address("Jerry.txt");
        //System.out.println(bobAddy);
        String addy = wal.address("Brennan.txt");
        wal.fund(addy, 100, "Brennan-funding.txt" );
        wal.transfer("Brennan.txt", bobAddy,10, "Brennan-to-Bob-transfer.txt" );
        System.out.println(wal.balance(bobAddy));
        System.out.println(wal.balance(addy));
        try {
            wal.verify("Brennan.txt", "Brennan-to-Bob-transfer.txt");
        }
        catch(Exception e){}
        wal.transfer("Brennan.txt", jerrdyAddy, 50, "Brennan-to-Jerry-transfer.txt" );
        try {
            wal.verify("Brennan.txt", "Brennan-to-Jerry-transfer.txt");
        }
        catch(Exception e){}
        wal.mine(1);
        wal.transfer("Brennan.txt", bobAddy, 5, "Brennan-to-Bob2-transfer.txt");
        wal.transfer("Jerry.txt", addy, 1, "Jerry-to-Brennan-transfer.txt");
        try {
            wal.verify("Brennan.txt", "Brennan-to-Bob2-transfer.txt");
            wal.verify("Jerry.txt", "Jerry-to-Brennan-transfer.txt");
        }catch (Exception e){}
        wal.mine(1);
    }
}

