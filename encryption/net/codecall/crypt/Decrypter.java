package net.codecall.crypt;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class Decrypter<T extends Serializable> {
	
	private CipherParams cipherParams;
	private ObjectInputStream objectInStream;
	
	public Decrypter(CipherParams cipherParams, String fileName) throws FileNotFoundException, 
			IOException {
		this.cipherParams = cipherParams;
		objectInStream = new ObjectInputStream(new FileInputStream(fileName));
	}
	
	@SuppressWarnings("unchecked")
	public T load() throws NoSuchAlgorithmException, 
			InvalidKeySpecException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException, 
			IllegalBlockSizeException, IOException, ClassNotFoundException, 
			BadPaddingException {
		Cipher cipher = getCipher(cipherParams);
		SealedObject sealedObject = (SealedObject)objectInStream.readObject();;
		return (T)sealedObject.getObject(cipher);
	}
	
	public void close() throws IOException {
		if (objectInStream != null) {
			objectInStream.close();
		}
	}
	
	private Cipher getCipher(CipherParams cipherParams) throws NoSuchAlgorithmException, 
			InvalidKeySpecException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException{
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(cipherParams.getSalt(), 20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(cipherParams.getPassphrase());
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(CipherParams.ALGORITHM);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(CipherParams.ALGORITHM);
	    cipher.init(Cipher.DECRYPT_MODE,secretKey,pbeParamSpec);
	    return cipher;
	}
}
