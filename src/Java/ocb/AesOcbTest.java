import java.util.Arrays;

public class AesOcbTest {

    public static String display(byte[] a, int off, int len) {
        String ret = "";
        String hex = "0123456789ABCDEF";
        for (int i = 0; i < len; i++) {
            int hi = (a[off + i] >>> 4) & 0x0f;
            int lo = (a[off + i]      ) & 0x0f;
            ret += hex.substring(hi, hi + 1) + hex.substring(lo, lo + 1);
        }
        return ret;
    }

    public static String display(byte[] a, int len) {
        return display(a, 0, len);
    }

    public static int memcmp(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return a.length - b.length;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return a[i] - b[i];
            }
        }
        return 0;
    }

    protected static String printHexString(byte[] buf, int pos, int len) {
        if (len == 0) {
            return "<empty string>";
        }
        if (len >= 40) {
            return display(buf, pos, 10) + " ... " + display(buf, pos + len - 10, 10) + " [" + len + " bytes]";
        }
        return display(buf, pos, len);
    }

    protected static int AES_KEY_BITLEN = 256;

    protected static void printOcbTestCase(int i, byte[] K, byte[] M) {
        OcbPmac keys = new OcbPmac();
        byte[] C, V;
        byte[] N = new byte[16];
        byte[] T = new byte[16];
        for (int t = 0; t < 15; t++) {
            N[t] = (byte)0;
        }
        N[15] = (byte)1;
    
        System.out.print("\n\nTest case  OCB-AES-" + AES_KEY_BITLEN + "-" + i + "B");
        System.out.print(  "\nKey        " + printHexString(K, 0, AES_KEY_BITLEN/8));
        System.out.print(  "\nPlaintext  " + printHexString(M, 0, i));

        keys.init(K, AES_KEY_BITLEN);
        C = keys.encrypt(M, 0, i, N, 0, T, 0);

        System.out.print(  "\nNonce      " + printHexString(N, 0, 16));
        System.out.print(  "\nCiphertext " + printHexString(C, 0,  i));
        System.out.print(  "\nTag        " + printHexString(T, 0, 16));

        V = keys.decrypt(C, 0, i, N, 0, T, 0);
        System.out.print(  "\nCheck      " + (V != null ? "OK" : "ERROR"));
    }

    public static void printOcbTestVectors() {
        byte[] pt = new byte[1000];
        byte[] key = new byte[32];

        for (int i = 0; i < key.length; i++) {
            key[i] = (byte)i;
        }
        for (int i = 0; i < 34; i++) {
            pt[i] = (byte)i;
        }
    
        printOcbTestCase(   0, key, pt);
        printOcbTestCase(   3, key, pt);
        printOcbTestCase(  16, key, pt);
        printOcbTestCase(  20, key, pt);
        printOcbTestCase(  32, key, pt);
        printOcbTestCase(  34, key, pt);
        Arrays.fill(pt, (byte)0);
        printOcbTestCase(1000, key, pt);
        System.out.println();
    }

    public static void rijndaelTest() {
        int i, err = 0;
        Rijndael aes = new Rijndael();
        byte[] cipherKey = new byte[256/8];
        byte[] pt = new byte[Rijndael.BLOCK_SIZE];
        byte[] ct = new byte[Rijndael.BLOCK_SIZE];
        byte[] vt = new byte[Rijndael.BLOCK_SIZE];

        System.out.println("Simple AES test");
        for (i = 0; i < cipherKey.length; i++) {
            cipherKey[i] = (byte)i;
        }
        for (i = 0; i < Rijndael.BLOCK_SIZE; i++) {
            pt[i] = (byte)(17*i);
        }
        System.out.println("pt: " + AesOcbTest.display(pt, Rijndael.BLOCK_SIZE));
        System.out.println("--------");

        // 128
        System.out.println("key " + AesOcbTest.display(cipherKey, 128/8));
        aes.makeKey(cipherKey, 128);
        aes.encrypt(pt, ct);
        System.out.println("ct: " + AesOcbTest.display(ct, Rijndael.BLOCK_SIZE));
        System.out.println("ex: 69C4E0D86A7B0430D8CDB78070B4C55A");
        if (memcmp(ct, new byte[] { (byte)0x69, (byte)0xC4, (byte)0xE0, (byte)0xD8,
                                    (byte)0x6A, (byte)0x7B, (byte)0x04, (byte)0x30,
                                    (byte)0xD8, (byte)0xCD, (byte)0xB7, (byte)0x80,
                                    (byte)0x70, (byte)0xB4, (byte)0xC5, (byte)0x5A}) == 0) {
            System.out.println(" OK!");
        } else {
            System.out.println(" ERROR!");
            err++;
        }
        aes.decrypt(ct, vt);
        System.out.println("vt: " + AesOcbTest.display(vt, Rijndael.BLOCK_SIZE));
        if (memcmp(vt, pt) == 0) {
            System.out.println(" OK!");
        } else {
            System.out.println(" ERROR!");
            err++;
        }
        System.out.println("--------");

        // 192
        System.out.println("key " + AesOcbTest.display(cipherKey, 192/8));
        aes.makeKey(cipherKey, 192);
        aes.encrypt(pt, ct);
        System.out.println("ct: " + AesOcbTest.display(ct, Rijndael.BLOCK_SIZE));
        System.out.println("ex: DDA97CA4864CDFE06EAF70A0EC0D7191");
        if (memcmp(ct, new byte[] { (byte)0xDD, (byte)0xA9, (byte)0x7C, (byte)0xA4,
                                    (byte)0x86, (byte)0x4C, (byte)0xDF, (byte)0xE0,
                                    (byte)0x6E, (byte)0xAF, (byte)0x70, (byte)0xA0,
                                    (byte)0xEC, (byte)0x0D, (byte)0x71, (byte)0x91}) == 0) {
            System.out.println(" OK!");
        } else {
            System.out.println(" ERROR!");
            err++;
        }
        aes.decrypt(ct, vt);
        System.out.println("vt: " + AesOcbTest.display(vt, Rijndael.BLOCK_SIZE));
        if (memcmp(vt, pt) == 0) {
            System.out.println(" OK!");
        } else {
            System.out.println(" ERROR!");
            err++;
        }
        System.out.println("--------");

        // 256
        System.out.println("key " + AesOcbTest.display(cipherKey, 256/8));
        aes.makeKey(cipherKey, 256);
        aes.encrypt(pt, ct);
        System.out.println("ct: " + AesOcbTest.display(ct, Rijndael.BLOCK_SIZE));
        System.out.println("ex: 8EA2B7CA516745BFEAFC49904B496089");
        if (memcmp(ct, new byte[] { (byte)0x8E, (byte)0xA2, (byte)0xB7, (byte)0xCA,
                                    (byte)0x51, (byte)0x67, (byte)0x45, (byte)0xBF,
                                    (byte)0xEA, (byte)0xFC, (byte)0x49, (byte)0x90,
                                    (byte)0x4B, (byte)0x49, (byte)0x60, (byte)0x89 }) == 0) {
            System.out.println(" OK!");
        } else {
            System.out.println(" ERROR!");
            err++;
        }
        aes.decrypt(ct, vt);
        System.out.println("vt: " + AesOcbTest.display(vt, Rijndael.BLOCK_SIZE));
        if (memcmp(vt, pt) == 0) {
            System.out.println(" OK!");
        } else {
            System.out.println(" ERROR!");
            err++;
        }
        System.out.println("--------");

        if (err == 0) {
            System.out.println("All tests OK!");
        } else {
            System.out.println("Number of errors: " + err);
        }
    }

    public static void main(String[] args) {
        rijndaelTest();
        printOcbTestVectors();
    }
}