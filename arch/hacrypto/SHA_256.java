package hacrypto;

public interface SHA_256 extends Hash {
  //@ public normal_behavior
  //@   requires (* digest length is always legal *);
  @Override public byte[] digest(byte[] message);

  //@ public normal_behavior
  //@   ensures \result == 256;
  @Override public int size();

  //@ public normal_behavior
  //@   ensures \result == 128;
  @Override public int security();
}
