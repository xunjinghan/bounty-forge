import java.nio.file.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

public class T7LocalDeser {
  public static void main(String[] args) throws Exception {
    String ckFile = args[0];
    String keyB64 = args.length > 1 ? args[1] : "kPH+bIxk5D2deZiIxcaaaA==";
    String raw = new String(Files.readAllBytes(Paths.get(ckFile)), "UTF-8").trim();
    byte[] all = Base64.getDecoder().decode(raw);
    byte[] key = Base64.getDecoder().decode(keyB64);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
           new IvParameterSpec(Arrays.copyOfRange(all, 0, 16)));
    byte[] pt;
    try {
      pt = c.doFinal(Arrays.copyOfRange(all, 16, all.length));
    } catch (Throwable t) {
      System.out.println("DECRYPT_ERR " + t.getClass().getName() + ": " + t.getMessage());
      return;
    }
    System.out.printf("COOKIE_LEN=%d RAW=%d PT_LEN=%d MAGIC=%02x%02x%02x%02x%n",
        raw.length(), all.length, pt.length, pt[0], pt[1], pt[2], pt[3]);
    System.out.println("CMD_MARKER_PRESENT=" + new String(pt, "ISO-8859-1").contains(args.length > 2 ? args[2] : "sleep"));
    long t0 = System.currentTimeMillis();
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(pt))) {
      Object o = ois.readObject();
      System.out.println("DESER_OK class=" + o.getClass().getName());
    } catch (Throwable t) {
      System.out.println("DESER_ERR " + t.getClass().getName() + ": " + t.getMessage());
    }
    System.out.println("ELAPSED_MS=" + (System.currentTimeMillis() - t0));
  }
}
