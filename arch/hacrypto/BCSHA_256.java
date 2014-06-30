package hacrypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class BCSHA_256 extends SHA256Digest implements SHA_256 {
  private final SHA256Digest sha256digest_singleton = new SHA256Digest();

  public byte[] digest(byte[] message) {
    byte[] result = new byte[sha256digest_singleton.getDigestSize()];
    sha256digest_singleton.update(message, 0, message.length);
    sha256digest_singleton.doFinal(result, 0);
    return result;
  }

  public String toString(byte[] digest) {
    return digest.toString();
  }

  public int size() {
    return 256;
  }

  public int security() {
    return 128;
  }
}

