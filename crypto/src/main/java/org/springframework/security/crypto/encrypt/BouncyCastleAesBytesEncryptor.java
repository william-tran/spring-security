/*
 * Copyright 2011-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.encrypt;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * Base class for AES-256 encryption using Bouncy Castle
 *
 * @author William Tran
 *
 */
public abstract class BouncyCastleAesBytesEncryptor implements BytesEncryptor {
	private static final boolean FOR_ENCRYPTION = true;
	private static final boolean FOR_DECRYPTION = false;

	private final KeyParameter secretKey;
	private final BytesKeyGenerator ivGenerator;

	public BouncyCastleAesBytesEncryptor(String password, CharSequence salt) {
		this(password, salt, KeyGenerators.secureRandom(16));
	}

	public BouncyCastleAesBytesEncryptor(String password, CharSequence salt,
			BytesKeyGenerator ivGenerator) {
		if (ivGenerator.getKeyLength() != 16) {
			throw new IllegalArgumentException("ivGenerator key length != block size 16");
		}
		this.ivGenerator = ivGenerator;
		PBEParametersGenerator keyGenerator = new PKCS5S2ParametersGenerator();
		byte[] pkcs12PasswordBytes = PBEParametersGenerator
				.PKCS5PasswordToUTF8Bytes(password.toCharArray());
		keyGenerator.init(pkcs12PasswordBytes, Hex.decode(salt), 1024);
		this.secretKey = (KeyParameter) keyGenerator.generateDerivedParameters(256);
	}

	@Override
	public byte[] encrypt(byte[] bytes) {
		byte[] iv = this.ivGenerator.generateKey();
		byte[] encrypted = process(FOR_ENCRYPTION, this.secretKey, iv, bytes);
		return iv != null ? concatenate(iv, encrypted) : encrypted;
	}

	@Override
	public byte[] decrypt(byte[] encryptedBytes) {
		byte[] iv = subArray(encryptedBytes, 0, this.ivGenerator.getKeyLength());
		encryptedBytes = subArray(encryptedBytes, this.ivGenerator.getKeyLength(),
				encryptedBytes.length);
		return process(FOR_DECRYPTION, this.secretKey, iv, encryptedBytes);
	}

	private byte[] process(boolean forEncryption, KeyParameter secretKey, byte[] iv,
			byte[] bytes) {
		OutputStreams outputStreams = getOutputStreams(forEncryption, secretKey, iv,
				bytes.length);
		try {
			outputStreams.cipherOutputStream.write(bytes);
			outputStreams.cipherOutputStream.close();
			return outputStreams.byteArrayOutputStream.toByteArray();
		}
		catch (IOException e) {
			throw new IllegalStateException(
					"unable to encrypt/decrypt due to IOException", e);
		}
		finally {
			try {
				outputStreams.cipherOutputStream.close();
			}
			catch (IOException e) {
			}
		}
	}

	abstract OutputStreams getOutputStreams(boolean forEncryption, KeyParameter secretKey,
			byte[] iv, int inputLength);

	static class OutputStreams {
		private final ByteArrayOutputStream byteArrayOutputStream;
		private final CipherOutputStream cipherOutputStream;

		public OutputStreams(ByteArrayOutputStream byteArrayOutputStream,
				CipherOutputStream cipherOutputStream) {
			super();
			this.byteArrayOutputStream = byteArrayOutputStream;
			this.cipherOutputStream = cipherOutputStream;
		}
	}

}
