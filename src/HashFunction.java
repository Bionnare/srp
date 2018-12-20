import java.security.MessageDigest;

public class HashFunction {
    private MessageDigest sha;

    public HashFunction() {
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] getHash(byte[] input) {
        sha.update(input);
        return sha.digest();
    }

    public byte[] getHash(byte[] input1, byte[] input2) {
        sha.update(input1);
        sha.update(input2);
        return sha.digest();
    }

    public byte[] getHash(String input) {
        return getHash(input.getBytes());
    }
}
