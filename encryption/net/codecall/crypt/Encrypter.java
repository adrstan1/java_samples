package net.codecall.crypt;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class Encrypter<T extends Serializable> {
	
	private CipherParams cipherParams;
	private ObjectOutputStream objOutStream;
	
	public Encrypter(CipherParams cipherParams, String fileName) throws NoSuchAlgorithmException, 
			FileNotFoundException, IOException {
		this.cipherParams = cipherParams;
		objOutStream = new ObjectOutputStream(new FileOutputStream(fileName));
	}
	
	public void store(T obj) throws NoSuchAlgorithmException, 
			InvalidKeySpecException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException, 
			IllegalBlockSizeException, IOException {
		Cipher cipher = getCipher(cipherParams);
		SealedObject sealedObject = new SealedObject(obj, cipher);
        objOutStream.writeObject(sealedObject);
	}
	
	public void close() throws IOException {
		if (objOutStream != null) {
			objOutStream.close();
		}
	}
	
	private Cipher getCipher(CipherParams cipherParams) throws NoSuchAlgorithmException, 
			InvalidKeySpecException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException {
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(cipherParams.getSalt(), 20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(cipherParams.getPassphrase());
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(CipherParams.ALGORITHM);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(CipherParams.ALGORITHM);
	    cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParamSpec);
	    return cipher;
	}
}
