package net.codecall.crypt;


public class CipherParams {
	// Use AES-256 in CBC mode, HMAC-SHA256, from the Bouncy Castle provider.
	public static final String ALGORITHM = "PBEWITHSHA256AND256BITAES-CBC-BC";
	public static final int BLOCK_SIZE = 32;
	private char[] passphrase;
	private byte[] salt;
	private int iterationCount;
	
	public CipherParams(String passphrase, byte[] salt, int iterationCount) {
		this.passphrase = passphrase.toCharArray();
		this.salt = salt;
		this.iterationCount = iterationCount;
	}
	
	public char[] getPassphrase() {
		return passphrase;
	}
	
	public byte[] getSalt() {
		return salt;
	}

	public int getIterationCount() {
		return iterationCount;
	}
}
