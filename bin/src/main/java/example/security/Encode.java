package example.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;

/*
 * This is the Main class.
 */
public class Encode {

  private final Argon2 argon2 = Argon2Factory.create();

  final Encryption rsa = new Encryption();

  private  byte[] compress(String hash) throws IOException {
    return GZIPCompression.compress(hash);
  }

  private  String decompress(byte[] hash) throws IOException {
    return GZIPCompression.decompress(hash);
  }

  public String hashpw(String plainText) {
      char[] passwordChars = plainText.toCharArray();

      String hash = argon2.hash(22, 65536, 1, passwordChars);

      argon2.wipeArray(passwordChars);

      try {

        byte[] newHash = encrypt(hash);

        return DatatypeConverter.printHexBinary(newHash);

      } catch (Exception e) {
        return null;
      }
  }

  public boolean verify(String plainText, String hashedStr) {
    try{

      byte[] hashArray = DatatypeConverter.parseHexBinary(hashedStr);

      hashedStr = decrypt(hashArray);

      return argon2.verify(hashedStr, plainText.toCharArray());

    } catch (Exception e) {

      System.out.println("Encode verify error");

      e.printStackTrace();

      return false;
    }
  }

  private byte[] encrypt(String hash) throws Exception {

    byte[] cipherText = rsa.do_RSAEncryption(hash);

    String newHash = DatatypeConverter.printHexBinary(cipherText);

    return compress(newHash);
  }

  private String decrypt(byte[] hash) throws Exception {

    String decompress = decompress(hash);

    return rsa.do_RSADecryption(DatatypeConverter.parseHexBinary(decompress));
  }
}
