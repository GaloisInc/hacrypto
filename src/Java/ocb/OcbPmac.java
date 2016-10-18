import java.util.Arrays;
import java.lang.IllegalArgumentException;

/**
 * OcbPmac.java
 *
 * A simple implementation of the offset codebook (OCB) mode of operation
 * and the parallel message authentication code (PMAC).
 *
 * @author: Paulo S. L. M. Barreto <paulo.barreto@terra.com.br>
 *
 * @version 1.0 (May 2001)
 *
 * This software is hereby placed in the public domain.
 *
 * Note that OCB mode itself is patent pending.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
public class OcbPmac {
    protected static final int  PRE_COMP_BLOCKS = 32;
    protected static final int  BLOCK_SIZE = Rijndael.BLOCK_SIZE;
    protected static final int  TAG_LENGTH = BLOCK_SIZE;

    protected Rijndael  aes     = null; // Underlying instance of the AES (Rijndael) cipher.
    protected byte[][]  L       = new byte[PRE_COMP_BLOCKS][BLOCK_SIZE]; // Precomputed L(i) values.
    protected byte[]    L_inv   = new byte[BLOCK_SIZE]; // Precomputed L/x value
    protected byte[]    tmp     = new byte[BLOCK_SIZE];
    protected byte[]    offset  = new byte[BLOCK_SIZE]; // Offset (Z[i]) for current block
    protected byte[]    chksum  = new byte[TAG_LENGTH]; // Checksum for computing tag

    protected static final void xorBlock(byte[] dst, int pos,
            byte[] src1, byte[] src2) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            dst[pos + i] = (byte)(src1[i] ^ src2[i]);
        }
    }

    protected static final void xorBlock(byte[] dst, byte[] src1,
            byte[] src2, int pos) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            dst[i] = (byte)(src1[i] ^ src2[pos + i]);
        }
    }

    protected static final void xorBlock(byte[] dst, byte[] src1, byte[] src2) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            dst[i] = (byte)(src1[i] ^ src2[i]);
        }
    }

    /**
     * Count the number of trailing zeroes in integer i.
     *
     * @return  0 <= ntz <= 32.
     */
    protected static final int ntz(int i) {
        /*
         * N.B. this function is not as bad as it might seem:
         * assuming the argument i is uniformly distributed,
         * the probability that ntz(i) = k is 2^(-k-1),
         * therefore the expected value of ntz(i) is < 1.
         */
        int result = 0;
        while ((i & 1) == 0) {
            i >>>= 1;
            result++;
        }
        return result;
    }

    public OcbPmac() {
    }

    public void finalize() {
        if (aes != null) {
            aes.finalize();
        }
        for (int i = 0; i < L.length; i++) {
            Arrays.fill(L[i], (byte)0);
        }
        Arrays.fill(L_inv,  (byte)0);
        Arrays.fill(tmp,    (byte)0);
        Arrays.fill(offset, (byte)0);
        Arrays.fill(chksum, (byte)0);
    }

    /**
     * Initialise the underlying AES cipher with a symmetric key.
     *
     * @param   cipherKey   the symmetric AES key.
     * @param   keyBits     the key size in bits (128, 192, or 256).
     *
     * @throws  IllegalArgumentException    if the key is null or
     *                      its length is not 128, 192, or 256.
     */
    public final void init(byte[] cipherKey, int keyBits)
            throws IllegalArgumentException {
        if (cipherKey == null) {
            throw new IllegalArgumentException("Null key");
        }
        if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
            throw new IllegalArgumentException("Invalid AES key size: " + keyBits + " bits.");
        }
        // Initialize AES keys
        if (aes == null) {
            aes = new Rijndael();
        }
        aes.makeKey(cipherKey, keyBits);

        // Precompute L[i]-values (L[0] is synonym of L)
        byte[] L0 = L[0];
        Arrays.fill(L0, (byte)0);
        aes.encrypt(L0, L0);
        for (int i = 1; i < PRE_COMP_BLOCKS; i++) {
            // L[i] = L[i - 1] * x
            byte[] L_cur = L[i], L_pre = L[i - 1];
            for (int t = 0; t < BLOCK_SIZE - 1; t++) {
                L_cur[t] = (byte)((L_pre[t] << 1) | ((L_pre[t + 1] >>> 7) & 1));
            }
            L_cur[BLOCK_SIZE - 1] = (byte)((L_pre[BLOCK_SIZE - 1] << 1) ^ ((L_pre[0] & 0x80) != 0 ? 0x87 : 0));
        }

        // Precompute L_inv = L / x = L * x^{-1}
        for (int i = BLOCK_SIZE - 1; i > 0; i--) {
            L_inv[i] = (byte)(((L0[i] & 0xff) >>> 1) | ((L0[i - 1] & 1) << 7));
        }
        L_inv[0] = (byte)((L0[0] & 0xff) >>> 1);
        if ((L0[BLOCK_SIZE - 1] & 1) != 0) {
            L_inv[0] ^= 0x80;
            L_inv[BLOCK_SIZE - 1] ^= 0x43;
        }
    }

    /**
     * Given a nonce starting at offset noncePos of the nonce byte array,
     * encrypt ptLen elements of byte array pt starting at offset ptPos, and
     * producing a tag starting at offset tagPos of the tag byte array.
     *
     * @param       pt          plaintext buffer.
     * @param       ptPos       start index of plaintext on pt.
     * @param       ptLen       byte length of plaintext.
     * @param       nonce       nonce array (BLOCK_SIZE bytes).
     * @param       noncePos    start index of nonce.
     * @param       tag         output tag buffer.
     * @param       tagPos      start index of tag.
     *
     * @return      the resulting ciphertext, a byte array of same length as pt.
     * 
     * @warning     pt, nonce, and tag must not overlap.
     */
    public final byte[] encrypt(byte[] pt, int ptPos, int ptLen,
            byte[] nonce, int noncePos, byte[] tag, int tagPos)
            throws IllegalArgumentException {
        if (aes == null) {
            throw new RuntimeException("AES key not initialized");
        }
        if (pt == null || ptPos < 0 || ptLen < 0 || pt.length - ptPos < ptLen) {
            throw new IllegalArgumentException("Missing or invalid plaintext");
        }
        if (nonce == null || noncePos < 0 || nonce.length - noncePos < BLOCK_SIZE) {
            throw new IllegalArgumentException("Missing or invalid nonce");
        }
        if (tag == null || tagPos < 0 || tag.length - tagPos < TAG_LENGTH) {
            throw new IllegalArgumentException("Missing or invalid tag");
        }

        // Create ciphertext
        byte[] ct = new byte[ptLen];
        int ctPos = 0;

        Arrays.fill(chksum, (byte)0);                       // Zero the checksum
        xorBlock(offset, L[0], nonce, noncePos);            // Calculate R, aka Z[0]
        aes.encrypt(offset, offset);

        // Process blocks 1 .. m-1
        int i;
        for (i = 1; ptLen > BLOCK_SIZE; i++) {
            xorBlock(chksum, chksum, pt, ptPos);            // Update the checksum
            xorBlock(offset, offset, L[ntz(i)]);            // Update the offset (Z[i] from Z[i-1])
            xorBlock(tmp, offset, pt, ptPos);               // xor the plaintext block with Z[i]
            aes.encrypt(tmp, tmp);                          // Encipher the block
            xorBlock(ct, ctPos, offset, tmp);               // xor Z[i] again, writing result to ciphertext pointer
            ptLen -= BLOCK_SIZE;
            ptPos += BLOCK_SIZE;
            ctPos += BLOCK_SIZE;
        }

        // Process block m
        xorBlock(offset, offset, L[ntz(i)]);                // Update the offset (Z[m] from Z[m-1])
        xorBlock(tmp, offset, L_inv);                       // xor L . x^{-1} and Z[m]
        tmp[BLOCK_SIZE - 1] ^= (byte)(ptLen << 3);          // Add in final block bit-length
        aes.encrypt(tmp, tmp);

        for (int t = 0; t < ptLen; t++) {
            ct[ctPos + t] = (byte)(pt[ptPos + t] ^ tmp[t]); // xor pt with block-cipher output to get ct
            tmp[t] = pt[ptPos + t];                         // Add to checksum the ptLen bytes of plaintext...
        }
        xorBlock(chksum, chksum, tmp);                      // ... followed by the last (16 - ptLen) bytes of block-cipher output

        // Calculate tag
        xorBlock(chksum, chksum, offset);
        aes.encrypt(chksum, tmp);
        System.arraycopy(tmp, 0, tag, tagPos, TAG_LENGTH);

        return ct;
    }

    /**
     * Given a nonce starting at offset noncePos of the nonce byte array,
     * decrypt ctLen elements of byte array ct starting at offset ctPos, and
     * verifying a tag starting at offset tagPos of the tag byte array.
     *
     * @param       ct          ciphertext buffer.
     * @param       ctPos       start index of ciphertext on ct.
     * @param       ctLen       byte length of ciphertext.
     * @param       nonce       nonce array (BLOCK_SIZE bytes).
     * @param       noncePos    start index of nonce.
     * @param       tag         input tag buffer.
     * @param       tagPos      start index of tag.
     *
     * @return      the resulting plaintext, a byte array of same length as ct
     *              if decryption is successfull, or else null if the tag does
     *              not correctly verify.
     * 
     * @warning     ct, nonce, and tag must not overlap.
     */
    public final byte[] decrypt(byte[] ct, int ctPos, int ctLen,
            byte[] nonce, int noncePos, byte[] tag, int tagPos)
            throws IllegalArgumentException {
        if (aes == null) {
            throw new RuntimeException("AES key not initialized");
        }
        if (ct == null || ctPos < 0 || ctLen < 0 || ct.length - ctPos < ctLen) {
            throw new IllegalArgumentException("Missing or invalid ciphertext");
        }
        if (nonce == null || noncePos < 0 || nonce.length - noncePos < BLOCK_SIZE) {
            throw new IllegalArgumentException("Missing or invalid nonce");
        }
        if (tag == null || tagPos < 0 || tag.length - tagPos < TAG_LENGTH) {
            throw new IllegalArgumentException("Missing or invalid tag");
        }

        // Create plaintext
        byte[] pt = new byte[ctLen];
        int ptPos = 0;

        Arrays.fill(chksum, (byte)0);               // Zero checksum
        xorBlock(offset, L[0], nonce, noncePos);    // Calculate R, aka Z[0]
        aes.encrypt(offset, offset);

        // Process blocks 1 .. m-1
        int i;
        for (i = 1; ctLen > BLOCK_SIZE; i++) {
            xorBlock(offset, offset, L[ntz(i)]);            // Update the offset (Z[i] from Z[i-1])
            xorBlock(tmp, offset, ct, ctPos);               // xor ciphertext block with Z[i]
            aes.decrypt(tmp, tmp);                          // Decipher the next block-cipher block
            xorBlock(pt, ptPos, offset, tmp);               // xor Z[i] again, writing result to plaintext pointer
            xorBlock(chksum, chksum, pt, ptPos);            // Update the checksum
            ctLen -= BLOCK_SIZE;
            ctPos += BLOCK_SIZE;
            ptPos += BLOCK_SIZE;
        }

        // Process block m
        xorBlock(offset, offset, L[ntz(i)]);                // Update the offset (Z[m] from Z[m-1])
        xorBlock(tmp, offset, L_inv);                       // xor L . x^{-1} and Z[m]
        tmp[BLOCK_SIZE - 1] ^= (byte)(ctLen << 3);          // Add in final block bit-length
        aes.encrypt(tmp, tmp);

        for (int t = 0; t < ctLen; t++) {
            pt[ptPos + t] = (byte)(ct[ctPos + t] ^ tmp[t]); // xor ct with block-cipher output to get pt
            tmp[t] = pt[ptPos + t];                         // Add to checksum the ctLen bytes of plaintext...
        }
        xorBlock(chksum, chksum, tmp);                      // ... followed by the last (16 - ptLen) bytes of block-cipher output

        // Calculate and verify tag
        xorBlock(chksum, chksum, offset);
        aes.encrypt(chksum, tmp);
        for (int t = 0; t < TAG_LENGTH; t++) {
            if (tmp[t] != tag[tagPos + t]) {
                Arrays.fill(pt, (byte)0);
                pt = null;
                break;
            }
        } 

        return pt;
    }

    /**
     * Compute the PMAC of dataLen elements of byte array data
     * starting at offset dataPos, and deposit the result
     * starting at offset tagPos of the tag byte array.
     *
     * @param       data        input data buffer.
     * @param       dataPos     start index of data.
     * @param       dataLen     byte length of data.
     * @param       tag         output tag buffer.
     * @param       tagPos      start index of tag.
     *
     * @return      the resulting PMAC.
     */
    public final void pmac(byte[] data, int dataPos, int dataLen,
            byte[] tag, int tagPos)
            throws IllegalArgumentException {
        if (aes == null) {
            throw new RuntimeException("AES key not initialized");
        }
        if (data == null || dataPos < 0 || dataLen < 0 || data.length - dataPos < dataLen) {
            throw new IllegalArgumentException("Missing or invalid data");
        }

        // Initializations
        Arrays.fill(chksum, (byte)0);
        Arrays.fill(offset, (byte)0);

        // Process blocks 1 .. m-1.   
        for (int i = 1; dataLen > BLOCK_SIZE; i++) {
            xorBlock(offset, offset, L[ntz(i)]);            // Update the offset (Z[i] from Z[i-1])
            xorBlock(tmp, offset, data, dataPos);           // xor input block with Z[i]
            aes.encrypt(tmp, tmp);
            // Update checksum and the loop variables
            xorBlock(chksum, chksum, tmp);
            dataPos += BLOCK_SIZE;
            dataLen -= BLOCK_SIZE;
        }

        // Process block m
        if (dataLen == BLOCK_SIZE) {    // full final block
            xorBlock(chksum, chksum, data, dataPos);
            xorBlock(chksum, chksum, L_inv);  
        } else {                        // short final block
            Arrays.fill(tmp, (byte)0);
            System.arraycopy(data, dataPos, tmp, 0, dataLen);
            tmp[dataLen] = (byte)0x80;
            xorBlock(chksum, chksum, tmp);
        }
        aes.encrypt(chksum, tmp);
        System.arraycopy(tmp, 0, tag, tagPos, TAG_LENGTH);
    }
}
