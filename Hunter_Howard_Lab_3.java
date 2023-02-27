package Hunter_Howard_Lab_3;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;

/***************************************************************
*Credit goes to Dr. Lawrence Thomas for writing the main function of this program.
*He wrote the main function and asked us to write the additional methods for an 
*assignment in our computer security class.
* 
* 
* Written by: Hunter Howard
* Due: 12/11/2022
* EECS4670 Computer Security - Lab 3 - Cryptography
* 
* lab3.java
* This project is divided into four different tasks that represent 
* different cryptographic concepts. 
* Task 1 decrypts a message by calculating m = (c^d)%N
* Task 2 finds a password/salt combo by comparing hashes
* Task 3 uses Fermat's Method to factor a BigInterger
* Task 4 uses the Chinese remainder Theorem to compute plaintext from a cyphertext
***************************************************************/

public class Hunter_Howard_Lab_3 {

	public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException
	{

		long StartTime = System.currentTimeMillis();
		BigInteger N, N1, N2, N3, C1, C2, C3, c, d, e, password_hash, N64;

		// Initialize each of the above variables here
		c =  new BigInteger("22e09cdd7ffa0ee3254194e2ada6449f4c89284fa0709f351267dacf40388ad94e7ff581196c3b89337503fb58c3d872714efe62a4098501d156da72a4cfd1dd5e06e48cb3bf95116a08a5e784f9f827b8de777ece2da7ea8225b50008e20c441228a75079798ad22e27c24de9d821c8ee7c72463fdc5f2d8795c72923d71f7d", 16);
		d =  new BigInteger("5a9532507751e0a540e8bdbc610716356333f74269308d6b99fa66712b6b3b1cf3b88be9083ede0a294702c9929849e997ce37b3638a1a25feca6fe2a608d52a13eaa4dade827fa4641bea06d0b37ee4742fee4135581aaf9cdd70fc80049131383f2f7cc29dfbdd9f43b7971997fe2a4d512583a4f2e72781c0dbb55e5b9c01", 16);
		N =  new BigInteger("ab74f9a758bdedf3f1e85480efefd8b2d1eeaff55b3b148e4029a4feb664212f315f1c2abca0b2765a81fb6400b93b29e40551e006220d9aeb89928d2ccd5515d1fa4d1694cb0961fa1b4bd126fc52ec354d9e9719984ee31913717baf7cfc6e09b9c6c5c28eddf9ce85a219e903e7cd992f618bdee886e15e4c1478772c8767", 16);
		e =  new BigInteger("10001", 16);
		N1 =  new BigInteger("a171f509ce3fe3829d3f1f7bb069b8aa8ae472720cfa4c3d3dbf76636cccaaf2a9ab35f9c3de6e62110fb155d3856ae3bef6e66659827bfa894fcf0f395157b773b0e15731e8e4982f05669551a6021ff110b0c5fd1d113e47e2e1a3c0f2dc2c5489323218aab0c0b0362adea37725999839d19a309d8ef43f3c356af8e21f09", 16);
		N2 =  new BigInteger("a66dd710dc53a7d6c0201b52ed887ac1d841ec99391e0d200965408dca914d49db0e50e7f17f354cbfdf49e7c58049bb15133e3cd7ae38a869afbfa091dad7b06902b02ac9c38b18ff42e96e65e80c387c2f91ab9a8fe58e44d7e6a0333229cd0e8a72c183c6b15c00f1bd4111c319a2a2d2bba1d12941fcb67c2b939e4fd72d", 16);
		N3 =  new BigInteger("98f785d12ace759f0964657ae1ffcd121851773f1718d93d6ded058e332aa96e96bc5421a6e8a404247f524ae87a1ef50eecd31a76b2f448609863ba02ae73ed19c3b9bb9ec6e594b70858dca30bbd372f6d1bdb1040157959b12017dd2f11b3de1d8d7a8b35cbabc720919ebae7acbe279144cdf415738ce408fbd33093623d", 16);
		C1 =  new BigInteger("14ce6dee638ab29a5004e4b9c2cb596694655260b28a7931822fec32164e45a58e9d0b519dc27f1723cca61ace78c0196ba63239ab049889a6609dd388309b81e329dda8a5ef691e0db20b9a0710f394e3150da3e22e2b8cac4f6b640be4ed00b0af6c33c299bf5f3e68a81e40e12c27fa9035377c01fc317c91c21055871bfa", 16);
		C2 =  new BigInteger("02db8a41a6fc157d8511ef40d11ab1f630225d8bec229ad0fc13818e28474adb2332edd4fd841c0f2c33b9629b8eee38022b184e9b8d5f26e7e29aa5064815f096995051ee61f6f262718d5a23bd099460d70f9487b169411f40dbe0368d8dd357c1ea50bf27a322270075eaa4ffac28ef30110a955d757cc7224f657e5eafcb", 16);
		C3 =  new BigInteger("8f6dfa30424193268f6e666b1e869fecc20cd59d74e3c3d92852d272e00cd1eeb3d61bcb08f2fd8d3103b87c33e02f3cd1e6e47de5aa284f0c66917ee5424d117303cf442c41b0f8827af800d701a0f63caaae6d90e40952889b19526f7d5b35a679e94ebe597244c7551a756e03b27d62caa2e0d0f6a5668455e6120fd28759", 16);
		password_hash =  new BigInteger("fb492a5fd1c7ea50a0cae04cdf464b46beea823502132692e6c34fcf78a11c55", 16);
		N64 =  new BigInteger("cd6273a337f86d5", 16);

		// Task 1
		System.out.println("Decrypting Message: " + decrypt_message(N, e, d, c));

		// Task 2
		System.out.print("Cracking Hashed Salted Password: ");
		String[] passwords = crack_hashed_password(password_hash, "Top_Passwords.txt");
		if (passwords == null) System.out.println("No matching passwords found");
		else System.out.println("Password = " + passwords[0] + " and salt = " + passwords[1]);

		// Task 3
		System.out.print("Factors of " + N64.toString() + ": ");
		BigInteger[] factors = get_factors(N64);
		if (factors == null) System.out.println("Unable to factor " + N64.toString());
		else System.out.println("Factor1: " + factors[0] + " Factor2: " + factors[1]);
		BigInteger PrivateKey = get_private_key_from_p_q_e(factors[0], factors[1], e);
		System.out.println("Private Key: " + PrivateKey.toString() + " (0x" + PrivateKey.toString(16) + ")");

		// Task 4
		System.out.println("Recovered Message: " + recoverMessage(N1, N2, N3, C1, C2, C3));	
		System.out.println("\nElapsed time: " + (System.currentTimeMillis() - StartTime) / 1000.0 + " seconds");
	}//END MAIN


	/******decrypt_message******--TASK 1
	* The purpose of this function is to read in 4 BigIntger values and
	* decrypt the given message by calculating m = (c^d)%N
	* The function returns the BigInteger m
	*/
	public static BigInteger decrypt_message(BigInteger N, BigInteger e, BigInteger d, BigInteger c) 
	{
		BigInteger m = c.modPow(d, N);
		return m;
	}


	/******crack_hashed_password******--TASK 2
	* The purpose of this function is to read in the text file "Top_Passwords.txt and a BigInteger
	* representing a hashed password/salt concatenation. It then reads through the text file and 
	* hashes every possible 2-word permutation using the SHA-256 algorithm
	* Each permutation is compared to the hash that was originally read in to determine the 
	* password/salt combination that was originally used
	* The function returns an array of two strings containing the password and salt
	*/
	public static String[] crack_hashed_password(BigInteger PWHash, String passwordList) throws FileNotFoundException, NoSuchAlgorithmException
	{
		String[] PasswordAndHash = new String[2];
		String password, salt, combined;
		File passwords = new File("Top_Passwords.txt");
		Scanner inputPassword = new Scanner(passwords), inputSalt = new Scanner(passwords);
		BigInteger HashBI;

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] hash;

		while(inputPassword.hasNextLine())
		{
			inputSalt = new Scanner(passwords); //reset scanner of salts to the top of the file
			password = inputPassword.nextLine();//read in our potential password
			while(inputSalt.hasNextLine())		//for every possible salt
			{
				salt = inputSalt.nextLine();			//get the salt
				combined = password+salt;				//concatenate with our current password
				hash = md.digest(combined.getBytes()); 	//hash it into our byte array
				HashBI = new BigInteger(1, hash); 		//convert the byte array to BigInteger
				if(HashBI.compareTo(PWHash) == 0)		//if our BigIntegers are equal
				{
					PasswordAndHash[0] = password;	//store our password
					PasswordAndHash[1] = salt;		//store our salt
					inputPassword.close();
					inputSalt.close();
					return PasswordAndHash;			//return our combo if found, otherwise...
				}
			}
		}											//try the next password
		inputPassword.close();
		inputSalt.close();
		PasswordAndHash = null;	//we didn't find a match
		return PasswordAndHash;
	}


	/******perfectSquare******--TASK 3
	* The purpose of this function is to read in a BigInteger value and determine
	* if it is a perfect square. It performs the sqrtAndRemainder function on the 
	* BigInt and returns a 2-BigInt array containing the square root and the remainder
	* if the remainder is 0, the BigInt is a perfect square
	*/
	public static BigInteger[] perfectSquare(BigInteger g)
	{
		BigInteger[] sqrtRemainder = new BigInteger[2];
		sqrtRemainder = g.sqrtAndRemainder();
		return sqrtRemainder;
	}


	/******get_factors******--TASK 3
	* The purpose of this function is to get a BigInteger value and 
	* factor it using Fermat's Method. It returns a 2-BigInt array
	* containing the two factors of the original BigInt
	* This function calls perfectSquare to determine if a number
	* is a perfect square as is required for Fermat's Method
	*/
	public static BigInteger[] get_factors(BigInteger N)
	{
		BigInteger[] factors = new BigInteger[2];
		BigInteger[] isPerfectSquare = new BigInteger[2];
		BigInteger one = new BigInteger("1");
		BigInteger zero = new BigInteger("0");
		BigInteger x = N.sqrt().add(one);
		BigInteger w, y, a, b;

		while(x.compareTo(N) == -1) //while x < n
		{
			w = x.pow(2).subtract(N);
			isPerfectSquare = perfectSquare(w);
			if(isPerfectSquare[1].compareTo(zero) == 0) //if w is a perfect square
			{
				y = w.sqrt();
				a = x.add(y);
				b = x.subtract(y);
				factors[0] = a;
				factors[1] = b;
				return factors;
			}
			x = x.add(one);
		}
		factors = null;
		return factors;
	}


	/******get_private_key_from_p_q_e******--TASK 3
	* The purpose of this function is to perform Euler's
	* Phi Function on a BigIntger N and then calculate a private key
	* using the equation d = (e^-1)% Phi(N)
	* The function returns a BigInteger d that represents the private key
	*/
	public  static BigInteger get_private_key_from_p_q_e(BigInteger p, BigInteger q, BigInteger e)
	{
		BigInteger PhiN, d;
		BigInteger one = new BigInteger("1");

		PhiN = (p.subtract(one).multiply(q.subtract(one))); //PhiN = (p-1)*(q-1)
		d = e.modInverse(PhiN);	 							//d = (e^-1)% Phi(N)
		return d;
	}


	/******recoverMessage******--TASK 4
	* The purpose of this function is to use the chinese remainder theorem to
	* calculate the plaintext from an intercepted cyphertext and return the 
	* Decoded message as a string. In order to do this the function is passed
	* three private keys and three matching cyphertexts 
	*/
	public static String recoverMessage(BigInteger N1, BigInteger N2, BigInteger N3, BigInteger C1, BigInteger C2, BigInteger C3)
	{
		BigInteger Invn1, Invn2, Invn3, N, n1, n2, n3, x;
		String message;

		N = N1.multiply(N2).multiply(N3);
		n1 = N.divide(N1);
		n2 = N.divide(N2);
		n3 = N.divide(N3);
		Invn1 = n1.modInverse(N1);
		Invn2 = n2.modInverse(N2);
		Invn3 = n3.modInverse(N3);

		x = C1.multiply(n1).multiply(Invn1);			//these 4 lines calculate:
		x = x.add((C2.multiply(n2).multiply(Invn2)));	//
		x = x.add((C3.multiply(n3).multiply(Invn3)));	//x = [(c1*n1*Invn1)+(c2*n2*Invn2)+(C3*n3*Invn3)]%N
		x = x.mod(N);									//

		x = third_root(x);		//get the cubed root of x

		byte[] code;
		code = x.toByteArray();		//convert x to a byte array 
		message = new String(code);	//convert the byte array to a string
		return message;				//return the message
	}


	/******third_root******--TASK 4
	* The purpose of this function is to find the 
	* cubed root of a BigInteger and return it as 
	* a BigInteger
	*/
	public static BigInteger third_root(BigInteger N)
	{	
		BigInteger root  = N.add(BigInteger.ONE);
		BigInteger N1  = N;
		BigInteger base = new BigInteger("3");
		BigInteger baseMinusOne = new BigInteger("2");

		while (N1.compareTo(root) == -1) 
		{
			root = N1;
			N1 = (N1.multiply(baseMinusOne).add(N.divide(N1.pow(2)))).divide(base);
		}
		return root;   
	}
}
