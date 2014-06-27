package hacrypto;

public interface SHA_1 extends Hash {
  //@ public normal_behavior
  //@   requires (* digest length is always legal *);
  @Override public byte[] digest(byte[] digest);

  //@ public normal_behavior
  //@   ensures \result == 160;
  @Override public int size();

  //@ public normal_behavior
  //@   ensures \result < 80;
  @Override public int security();
}

