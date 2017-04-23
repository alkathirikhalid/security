[![](https://jitpack.io/v/alkathirikhalid/security.svg)](https://jitpack.io/#alkathirikhalid/security)

# security
<h1>A utility for secure one-way and two-way encryption.</h1>
<h2>AES (encrypt / decrypt)</h2>
<p>Advanced Encryption Standard utility. Provides a way to Encrypt and Decrypt texts. It is important to note this utility class is only applicable for UTF input types and more secure ways might be required for different applications.</p>
<p>Quick Usage:<br/><code>AES.encrypt(plainText, encryptionKey, IV);</code><br/><code>AES.decrypt(cipherText, encryptionKey, IV);</code></p>
<p>The IV can either be passed into the encrypt method or be generated <code>SaltAndHash.getSalt().substring(0, 16);</code><br/>The Class also has a self adjust private inner class <code>checkAndPatch(plainText)</code>That allows an input text of a value other than 16 bytes or 128 bits to be encrypted, both the <code>encryptionKey</code> and <code> IV</code> still needs to be 16 bytes or 128 bits this can easily be generate as explain previously on IV.</p>
<h2>SaltAndHash</h2>
<p>Provides a way to get salt and hash passwords. It is important to note this utility class is configurable based on the standard hashing algorithms provided by the Java MessageDigest for SHA-1, SHA-256, SHA-384, SHA-512.</p>
<p>Quick Usage:<br/><code>SaltAndHash.getSalt();</code><br/><code>SaltAndHash.hashPassword(password, salt)</code> // Default "SHA-512"<br/><code>SaltAndHash.hashPassword(password, salt, messageDisgest)</code> // Pass a hashing algorithms that is required</p>
# Installation
### Gradle
```
allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
```
```
dependencies {
	        compile 'com.github.alkathirikhalid:security:v1.01'
	}
  ```
### Maven
  ```
  <repositories>
		<repository>
		    <id>jitpack.io</id>
		    <url>https://jitpack.io</url>
		</repository>
	</repositories>
  ```
  ```
  <dependency>
	    <groupId>com.github.alkathirikhalid</groupId>
	    <artifactId>security</artifactId>
	    <version>v1.01</version>
	</dependency>
  ```
  
# Further Resources
<ul>
<li>Document download: https://github.com/alkathirikhalid/security/releases/download/v1.01/apidocs.zip</li>
<li>Jar download: https://github.com/alkathirikhalid/security/releases/download/v1.01/Security-v1.01.jar</li>
</ul>
  
# License

Copyright 2015 Al-Kathiri Khalid www.alkathirikhalid.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

