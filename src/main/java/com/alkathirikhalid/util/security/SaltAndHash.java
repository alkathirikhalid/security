/*
 * Copyright 2015 Al-Kathiri Khalid www.alkathirikhalid.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alkathirikhalid.util.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

/**
 * <p>Salt And Hash utility Class for Passwords.</p>
 * <p>Provides a way to get salt and hash passwords.</p>
 * <p><strong>It is important to note this utility class is configurable based on
 * the standard hashing algorithms provided by the Java MessageDigest for SHA-1,
 * SHA-256, SHA-384, SHA-512</strong>.</p>
 *
 * @author alkathirikhalid
 * @version 1.01
 */
public class SaltAndHash {

    /**
     * <p><code>SaltAndHash</code> instances should <strong>NOT</strong> be
     * created. The class should be used as:
     * <code>SaltAndHash.getSalt();</code>.</p>
     */
    private SaltAndHash() {
    }

    /**
     * <p>Generates salt using Secure Random.</p>
     *
     * @return 352 bit, 44 long character string to be used as salt
     */
    public static String getSalt() {

        Random random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);

    }

    /**
     * <p>Hash password by combining password with salt.</p>
     *
     * @param password the plain input text to be salted and hashed.
     * @param salt the generated value from <code>getSalt();</code>.
     * @return a String to be stored in database.
     * @throws NoSuchAlgorithmException thrown when a particular cryptographic
     * algorithm is requested but is not available in the environment.
     */
    public static String hashPassword(String password, String salt) throws NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        messageDigest.reset();
        messageDigest.update((password + salt).getBytes());
        byte[] messageDigestArray = messageDigest.digest();
        StringBuilder stringBuilder = new StringBuilder(messageDigestArray.length * 2);
        for (byte b : messageDigestArray) {
            int v = b & 0xff;
            if (v < 16) {
                stringBuilder.append('0');
            }
            stringBuilder.append(Integer.toHexString(v));
        }
        return (stringBuilder.toString());
    }

    /**
     * <p>Hash password by combining password with salt.</p>
     *
     * @param password the plain input text to be salted and hashed.
     * @param salt the generated value from <code>getSalt();</code>.
     * @param messageDisgest the mode used either MD5, SHA-1 SHA-256 SHA-384
     * SHA-512 for a secure one-way hash function.
     * @return a String to be stored in database.
     * @throws NoSuchAlgorithmException thrown when a particular cryptographic
     * algorithm is requested but is not available in the environment.
     */
    public static String hashPassword(String password, String salt, String messageDisgest) throws NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance(messageDisgest);
        messageDigest.reset();
        messageDigest.update((password + salt).getBytes());
        byte[] messageDigestArray = messageDigest.digest();
        StringBuilder stringBuilder = new StringBuilder(messageDigestArray.length * 2);
        for (byte b : messageDigestArray) {
            int v = b & 0xff;
            if (v < 16) {
                stringBuilder.append('0');
            }
            stringBuilder.append(Integer.toHexString(v));
        }
        return (stringBuilder.toString());
    }
}
