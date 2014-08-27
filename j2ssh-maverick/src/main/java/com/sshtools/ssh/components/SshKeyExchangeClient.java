
package com.sshtools.ssh.components;

import java.io.IOException;
import java.math.BigInteger;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh2.TransportProtocol;

/**
 *
 * <p>Abstract representation of an SSH key exchange.</p>
 * @author Lee David Painter
 */
public abstract class SshKeyExchangeClient implements SshKeyExchange {

  String hashAlgorithm;
  
  protected SshKeyExchangeClient(String hashAlgorithm) {
	  this.hashAlgorithm = hashAlgorithm;
  }
  
  /**
   * The secret value produced during key exchange.
   */
  protected BigInteger secret;

  /**
   * The exchange hash produced during key exchange.
   */
  protected byte[] exchangeHash;

  /**
   * The server's host key.
   */
  protected byte[] hostKey;

  /**
   * The signature generated over the exchange hash
   */
  protected byte[] signature;

  /**
   * The transport protocol for sending/receiving messages
   */
  protected TransportProtocol transport;

  /**
   * Contruct an uninitialized key exchange
   */
  public SshKeyExchangeClient() {
  }

  /**
   * Get the key exchange algorithm name.
   * @return the key exchange algorithm.
   */
  public abstract String getAlgorithm();

  /**
   * Get the output of the key exchange
   * @return the exchange hash output.
   */
  public byte[] getExchangeHash() {
    return exchangeHash;
  }

  /**
   * Get the host key supplied during key exchange.
   * @return the server's host key
   */
  public byte[] getHostKey() {
    return hostKey;
  }

  /**
   * Get the secret value produced during key exchange.
   * @return The secret value producted during key exchange
   */
  public BigInteger getSecret() {
    return secret;
  }

  /**
   * Get the signature produced during key exchange.
   * @return the signature produced from the exchange hash.
   */
  public byte[] getSignature() {
    return signature;
  }
  
  public String getHashAlgorithm() {
	  return hashAlgorithm;
  }

  /**
   * Initialize the key exchange.
   * @param transport
   * @throws IOException
   */
  public void init(TransportProtocol transport, boolean ignoreFirstPacket) {
    this.transport = transport;
  }

  /**
   * Override to perform the client side key exchange. The implementation should
   * not return until all messages have been sent.
   * @param clientId
   * @param serverId
   * @param clientKexInit
   * @param serverKexInit
   * @throws IOException
   */
  public abstract void performClientExchange(String clientId,
                                             String serverId,
                                             byte[] clientKexInit,
                                             byte[] serverKexInit) throws
      SshException;


  public abstract boolean isKeyExchangeMessage(int messageid);

  /**
   * Reset the key exchange.
   */
  public void reset() {
    exchangeHash = null;
    hostKey = null;
    signature = null;
    secret = null;
  }
}
