package net.codecall.crypt;

import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Demo {
	public static void main(String[] args) {
		Encrypter<Person> encrypter = null;
		Decrypter<Person> decrypter = null;
		try {
			Security.addProvider(new BouncyCastleProvider());
			
			byte[] salt = new byte[CipherParams.BLOCK_SIZE];
			SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
			rand.nextBytes(salt);
			
			// Store a person in encrypted format.
			Person person1 = new Person("Doe", "John", 34);
			CipherParams cipherParams = new CipherParams("secret", salt, 1000);
			encrypter = new Encrypter<Person>(cipherParams, "Person.ser");
			encrypter.store(person1);
			System.out.println(person1);
			
			// Load a person and decrypt
			decrypter = new Decrypter<Person>(cipherParams, "Person.ser");
			Person person2 = decrypter.load();
			System.out.println(person2);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (encrypter != null) {
					encrypter.close();
				}
				if (decrypter != null) {
					decrypter.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
