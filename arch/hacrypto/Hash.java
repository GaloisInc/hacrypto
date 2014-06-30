package hacrypto;

public interface Hash {
  //@ public normal_behavior
  //@   ensures \result.length == size();
  public byte[] digest(byte[] message);

  // @refines print
  public String toString(byte[] digest);

  //@ public normal_behavior
  //@   ensures 0 < \result;
  public int size();

  //@ public normal_behavior
  //@   ensures 0 < \result;
  public int security();
}
