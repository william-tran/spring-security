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

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;

/**
 * An Encryptor equivalent to {@link AesBytesEncryptor} using
 * {@link CipherAlgorithm#GCM} that uses BouncyCastle instead of JCE. The
 * algorithm is equivalent to "AES/GCM/NoPadding".
 *
 * @author William Tran
 *
 */
public class BouncyCastleAesGcmBytesEncryptor extends BouncyCastleAesBytesEncryptor {

	public BouncyCastleAesGcmBytesEncryptor(String password, CharSequence salt) {
		super(password, salt);
	}

	public BouncyCastleAesGcmBytesEncryptor(String password, CharSequence salt,
			BytesKeyGenerator ivGenerator) {
		super(password, salt, ivGenerator);
	}

	@Override
	OutputStreams getOutputStreams(boolean forEncryption, KeyParameter secretKey,
			byte[] iv, int inputLength) {
		GCMBlockCipher blockCipher = new GCMBlockCipher(new AESFastEngine());
		blockCipher.init(forEncryption, new AEADParameters(secretKey, 128, iv));
		ByteArrayOutputStream out = new ByteArrayOutputStream(
				blockCipher.getOutputSize(inputLength));
		CipherOutputStream cipherOutputStream = new CipherOutputStream(out, blockCipher);
		return new OutputStreams(out, cipherOutputStream);
	}

}
