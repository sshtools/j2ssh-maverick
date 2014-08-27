/**
 * Copyright 2003-2014 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.sshtools.publickey;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.SshDsaPrivateKey;
import com.sshtools.ssh.components.SshDsaPublicKey;
import com.sshtools.ssh.components.SshKeyPair;
import com.sshtools.ssh.components.SshRsaPrivateCrtKey;
import com.sshtools.util.SimpleASNReader;
import com.sshtools.util.SimpleASNWriter;

class OpenSSHPrivateKeyFile
   implements SshPrivateKeyFile {

  byte[] formattedkey;

  OpenSSHPrivateKeyFile(byte[] formattedkey)
     throws IOException {
    if(!isFormatted(formattedkey)) {
      throw new IOException(
         "Formatted key data is not a valid OpenSSH key format");
    }
    this.formattedkey = formattedkey;
  }

  OpenSSHPrivateKeyFile(SshKeyPair pair, String passphrase)
     throws IOException {
    formattedkey = encryptKey(pair, passphrase);
  }

  /* (non-Javadoc)
   * @see com.sshtools.publickey.SshPrivateKeyFile#isPassphraseProtected()
   */
  public boolean isPassphraseProtected() {
    try {
      Reader r = new StringReader(new String(formattedkey, "US-ASCII"));
      PEMReader pem = new PEMReader(r);

      return pem.getHeader().containsKey("DEK-Info");
    }
    catch(IOException e) {
      return true;
    }
  }

  public String getType() {
    return "OpenSSH";
  }

  public boolean supportsPassphraseChange() {
    return true;
  }

  public SshKeyPair toKeyPair(String passphrase)
     throws IOException, InvalidPassphraseException {

    Reader r = new StringReader(new String(formattedkey, "US-ASCII"));
    PEMReader pem = new PEMReader(r);
    byte[] payload = pem.decryptPayload(passphrase);
    SimpleASNReader asn = new SimpleASNReader(payload);

    try {
        if (PEM.DSA_PRIVATE_KEY.equals(pem.getType())) {
            return getDSAKeyPair(asn);
        } else if (PEM.RSA_PRIVATE_KEY.equals(pem.getType())) {
            return getRSAKeyPair(asn);
        } else {
            throw new IOException("Unsupported type: "
                                  + pem.getType());
        }
    } catch(IOException ex) {
        throw new InvalidPassphraseException(ex);
    }
  }

  SshKeyPair getRSAKeyPair(SimpleASNReader asn)
     throws
     IOException {

		try {
			asn.assertByte(0x30); // SEQUENCE

			asn.getLength();
			asn.assertByte(0x02); // INTEGER (version)

			asn.getData();
			asn.assertByte(0x02); // INTEGER ()

			BigInteger modulus = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger publicExponent = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger privateExponent = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger primeP = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger primeQ = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger primeExponentP = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger primeExponentQ = new BigInteger(asn.getData());
			asn.assertByte(0x02); // INTEGER ()

			BigInteger crtCoefficient = new BigInteger(asn.getData());

			SshKeyPair pair = new SshKeyPair();
			pair.setPublicKey(ComponentManager.getInstance().createRsaPublicKey(modulus, publicExponent));
			pair.setPrivateKey(ComponentManager.getInstance().createRsaPrivateCrtKey(modulus,
			                                       publicExponent,
			                                       privateExponent,
			                                       primeP, primeQ,
			                                       primeExponentP,
			                                       primeExponentQ,
			                                       crtCoefficient));

			return pair;
		} catch (SshException e) {
			throw new SshIOException(e);
		}

  }

  SshKeyPair getDSAKeyPair(SimpleASNReader asn)
     throws
     IOException {

	    try {
			asn.assertByte(0x30); // SEQUENCE
			asn.getLength();

			asn.assertByte(0x02); // INTEGER (version)
			asn.getData();

			asn.assertByte(0x02); // INTEGER (p)
			BigInteger p = new BigInteger(asn.getData());

			asn.assertByte(0x02); // INTEGER (q)
			BigInteger q = new BigInteger(asn.getData());

			asn.assertByte(0x02); // INTEGER (g)
			BigInteger g = new BigInteger(asn.getData());

			asn.assertByte(0x02); // INTEGER (y)
			BigInteger y = new BigInteger(asn.getData());

			asn.assertByte(0x02); // INTEGER (x)
			BigInteger x = new BigInteger(asn.getData());

			SshKeyPair pair = new SshKeyPair();
                        SshDsaPublicKey pub = ComponentManager.getInstance().createDsaPublicKey(p, q, g, y);
                        pair.setPublicKey(pub);

			pair.setPrivateKey(ComponentManager.getInstance().createDsaPrivateKey(p, q, g, x, pub.getY()));

			return pair;
		} catch (SshException e) {
			throw new SshIOException(e);
		}
  }

  void writeDSAKeyPair(SimpleASNWriter asn, SshDsaPrivateKey privatekey,
                       SshDsaPublicKey publickey) {
    // Write to a substream temporarily.
    // This code needs to know the length of the substream before it can write the data from
    // the substream to the main stream.
    SimpleASNWriter asn2 = new SimpleASNWriter();

    asn2.writeByte(0x02); // INTEGER (version)

    byte[] version = new byte[1];
    asn2.writeData(version);
    asn2.writeByte(0x02); // INTEGER (p)
    asn2.writeData(publickey.getP().toByteArray());
    asn2.writeByte(0x02); // INTEGER (q)
    asn2.writeData(publickey.getQ().toByteArray());
    asn2.writeByte(0x02); // INTEGER (g)
    asn2.writeData(publickey.getG().toByteArray());
    asn2.writeByte(0x02); // INTEGER (y)
    asn2.writeData(publickey.getY().toByteArray());
    asn2.writeByte(0x02); // INTEGER (x)
    asn2.writeData(privatekey.getX().toByteArray());

    byte[] dsaKeyEncoded = asn2.toByteArray();

    asn.writeByte(0x30); // SEQUENCE
    asn.writeData(dsaKeyEncoded);
  }

  void writeRSAKeyPair(SimpleASNWriter asn, SshRsaPrivateCrtKey privatekey) {
    // Write to a substream temporarily.
    // This code needs to know the length of the substream before it can write the data from
    // the substream to the main stream.
    SimpleASNWriter asn2 = new SimpleASNWriter();

    asn2.writeByte(0x02); // INTEGER (version)

    byte[] version = new byte[1];
    asn2.writeData(version);
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getModulus().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getPublicExponent().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getPrivateExponent().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getPrimeP().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getPrimeQ().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getPrimeExponentP().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getPrimeExponentQ().toByteArray());
    asn2.writeByte(0x02); // INTEGER ()
    asn2.writeData(privatekey.getCrtCoefficient().toByteArray());

    byte[] rsaKeyEncoded = asn2.toByteArray();

    asn.writeByte(0x30); // SEQUENCE
    asn.writeData(rsaKeyEncoded);
  }

  public byte[] encryptKey(SshKeyPair pair, String passphrase)
     throws IOException {

    byte[] payload;
    PEMWriter pem = new PEMWriter();
    SimpleASNWriter asn = new SimpleASNWriter();
    if(pair.getPublicKey()instanceof SshDsaPublicKey) {
      writeDSAKeyPair(asn, (SshDsaPrivateKey)pair.getPrivateKey(),
                      (SshDsaPublicKey)pair.getPublicKey());
      payload = asn.toByteArray();
      pem.setType(PEM.DSA_PRIVATE_KEY);

    }
    else if(pair.getPrivateKey()instanceof SshRsaPrivateCrtKey) {
      writeRSAKeyPair(asn, (SshRsaPrivateCrtKey)pair.getPrivateKey());
      payload = asn.toByteArray();
      pem.setType(PEM.RSA_PRIVATE_KEY);
    }
    else {
      throw new IOException(pair.getPublicKey().getAlgorithm() +
                            " is not supported");
    }

    pem.encryptPayload(payload, passphrase);

    StringWriter w = new StringWriter();
    pem.write(w);

    return w.toString().getBytes("UTF-8");
  }

  /* (non-Javadoc)
   * @see com.sshtools.publickey.SshPrivateKeyFile#changePassphrase(java.lang.String, java.lang.String)
   */
  public void changePassphrase(String oldpassphrase, String newpassphrase)
     throws IOException, InvalidPassphraseException {
    SshKeyPair pair = toKeyPair(oldpassphrase);
    formattedkey = encryptKey(pair, newpassphrase);
  }

  public byte[] getFormattedKey() {
    return formattedkey;
  }

  public static boolean isFormatted(byte[] formattedkey) {
    try {
      Reader r = new StringReader(new String(formattedkey, "UTF-8"));
//      PEMReader pem = 
    	  new PEMReader(r);
      return true;
    }
    catch(IOException e) {
      return false;
    }
  }

}
