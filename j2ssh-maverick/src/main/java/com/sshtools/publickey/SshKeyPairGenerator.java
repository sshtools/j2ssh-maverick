
package com.sshtools.publickey;

import java.io.IOException;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.SshKeyPair;


/**
 * <p>Generate public/private key pairs.</p>
 * <p>
 * To generate a new pair use the following code
 * <blockquote><pre>
 * SshKeyPair pair = SshKeyPairGenerator.generateKeyPair(SshKeyPairGenerator.SSH2_RSA,
 *                                                       1024);
 * </pre></blockquote>
 * To create formatted key file for the public key use:
 * <blockquote><pre>
     * SshPublicKeyFile pubfile = SshPublicKeyFileFactory.create(pair.getPublicKey(),
 *                        "Some comment",
 *                        SshPublicKeyFileFactory.OPENSSH_FORMAT);
 * FileOutputStream fout = new FileOutputStream("mykey.pub");
 * fout.write(pubfile.getFormattedKey());
 * fout.close();
 * </pre><blockquote>
 * To create a formatted, encrypted private key file use:
 * <blockquote><pre>
 * SshPrivateKeyFile prvfile = SshPrivateKeyFileFactory.create(pair,
 *                        "my passphrase",
 *                        "Some comment",
 *                        SshPrivateKeyFileFactory.OPENSSH_FORMAT);
 * FileOutputStream fout = new FileOutputStream("mykey");
 * fout.write(prvfile.getFormattedKey());
 * fout.close();
 * </pre><blockquote>
 * </p>
 * @author Lee David Painter
 */
public class SshKeyPairGenerator {

  public static final String SSH1_RSA = "rsa1";
  public static final String SSH2_RSA = "ssh-rsa";
  public static final String SSH2_DSA = "ssh-dss";

  /**
   * Generates a new key pair.
   * @param algorithm
   * @param bits
   * @return SshKeyPair
   * @throws IOException
   */
  public static SshKeyPair generateKeyPair(String algorithm, int bits) throws
      IOException, SshException {

    if (!SSH2_RSA.equalsIgnoreCase(algorithm) &&
        !SSH2_DSA.equalsIgnoreCase(algorithm)) {
      throw new IOException(algorithm + " is not a supported key algorithm!");
    }

    SshKeyPair pair = new SshKeyPair();

    if (SSH2_RSA.equalsIgnoreCase(algorithm)) {
      pair = ComponentManager.getInstance().generateRsaKeyPair(bits);
    }
    else {
      pair = ComponentManager.getInstance().generateDsaKeyPair(bits);
    }

    return pair;
  }

}
