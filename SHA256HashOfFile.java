import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class SHA256HashOfFile {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        String filePath = "Abstract.docx";   // Enter the Paht of file in this
        byte[] fileBytes = getFileBytes(filePath);
        byte[] hashBytes = getSHA256Hash(fileBytes);
        String hashString = bytesToHex(hashBytes);
        System.out.println(hashString);
    }

    private static byte[] getFileBytes(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] fileBytes = new byte[(int) file.length()];
        fis.read(fileBytes);
        fis.close();
        return fileBytes;
    }

    private static byte[] getSHA256Hash(byte[] bytes) {
        int[] words = padMessage(bytes);
        int[] state = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        for (int i = 0; i < words.length; i += 16) {
            int[] block = new int[64];
            System.arraycopy(words, i, block, 0, 16);
            for (int j = 16; j < 64; j++) {
                int s0 = rightRotate(block[j - 15], 7) ^ rightRotate(block[j - 15], 18) ^ (block[j - 15] >>> 3);
                int s1 = rightRotate(block[j - 2], 17) ^ rightRotate(block[j - 2], 19) ^ (block[j - 2] >>> 10);
                block[j] = block[j - 16] + s0 + block[j - 7] + s1;
            }
            int a = state[0];
            int b = state[1];
            int c = state[2];
            int d = state[3];
            int e = state[4];
            int f = state[5];
            int g = state[6];
            int h = state[7];
            for (int j = 0; j < 64; j++) {
                int S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                int ch = (e & f) ^ (~e & g);
                int temp1 = h + S1 + ch + K[j] + block[j];
                int S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = S0 + maj;
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }
        byte[] hashBytes = new byte[32];
        for (int i = 0; i < 8; i++) {
            hashBytes[i * 4] = (byte) (state[i] >>> 24);
            hashBytes[i * 4 + 1] = (byte) (state[i] >>> 16);
            hashBytes[i * 4 + 2] = (byte) (state[i] >>> 8);
            hashBytes[i * 4 + 3] = (byte) state[i];
        }
        return hashBytes;
    }

    private static int[] padMessage(byte[] message) {
        int messageLength = message.length;
        int numBlocks = ((messageLength + 8) / 64) + 1;
        int[] words = new int[numBlocks * 16];
        int i;
        for (i = 0; i < messageLength; i++) {
            words[i / 4] |= (message[i] & 0xff) << (24 - (i % 4) * 8);
        }
        words[i / 4] = 0x80 << (24 - (i % 4) * 8);
        words[numBlocks * 16 - 1] = messageLength * 8;
        return words;
    }

    private static int rightRotate(int value, int distance) {
        return (value >>> distance) | (value << (32 - distance));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
}
