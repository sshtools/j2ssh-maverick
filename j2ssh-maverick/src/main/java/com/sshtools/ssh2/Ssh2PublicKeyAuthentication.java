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

package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.PublicKeyAuthentication;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshRsaPublicKey;
import com.sshtools.util.ByteArrayWriter;


/**
 * SSH2 public key authentication providing additional SSH2 public key authentication
 * features. This implementation extends basic public key authentication to provide
 * the ability to pre-check whether a public key is acceptable to the server. Use exactly
 * the same as <a href="../ssh/PublicKeyAuthentication.html>PublicKeyAuthentication</a>
 * except that a flag can be set to turn off the actual authenticating process, instead the
 * authentication process will return PUBLIC_KEY_ACCEPTABLE as the authentication result
 * if the server would accept the key.
 *
 *  @author Lee David Painter
 *
 */
public class Ssh2PublicKeyAuthentication
    extends PublicKeyAuthentication
    implements AuthenticationClient {

  final static int SSH_MSG_USERAUTH_PK_OK = 60;
  SignatureGenerator generator;

  public Ssh2PublicKeyAuthentication() {
  }

  /* (non-Javadoc)
   * @see com.maverick.ssh2.AuthenticationClient#authenticate(com.maverick.ssh2.AuthenticationProtocol, java.lang.String)
   */
  public void authenticate(
      AuthenticationProtocol authentication,
      String servicename) throws SshException, AuthenticationResult {

	ByteArrayWriter baw = new ByteArrayWriter();
    
	try {
      if(getPublicKey() == null) {
        throw new SshException("Public key not set!",
                               SshException.BAD_API_USAGE);
      }
      if((getPrivateKey() == null && generator == null) && isAuthenticating()) {
        throw new SshException("Private key or signature generator not set!",
                               SshException.BAD_API_USAGE);
      }
      if(getUsername() == null) {
        throw new SshException("Username not set!",
                               SshException.BAD_API_USAGE);
      }

      // Generate the data to sign
      
      baw.writeBinaryString(authentication.getSessionIdentifier());
      baw.write(AuthenticationProtocol.SSH_MSG_USERAUTH_REQUEST);
      baw.writeString(getUsername());
      baw.writeString(servicename);
      baw.writeString("publickey");
      baw.writeBoolean(isAuthenticating());

      byte[] encoded;

      /**
       * Try an SSH1 key over SSH2, not sure whether this actually works in practice
       * but it stops the authentication from falling over with EOFException and allows a
       * normal failure.
       */
      try {
          if (getPublicKey() instanceof SshRsaPublicKey && ((SshRsaPublicKey)getPublicKey()).getVersion()==1) {

        	  SshRsaPublicKey pk = (SshRsaPublicKey) getPublicKey();
              baw.writeString("ssh-rsa");
              ByteArrayWriter baw2 = new ByteArrayWriter();

              try {
	              baw2.writeString("ssh-rsa");
	              baw2.writeBigInteger(pk.getPublicExponent());
	              baw2.writeBigInteger(pk.getModulus());
	
	              baw.writeBinaryString(encoded = baw2.toByteArray());
              } finally {
            	  baw2.close();
              }
          } else {
                  baw.writeString(getPublicKey().getAlgorithm());
                  baw.writeBinaryString(encoded = getPublicKey().getEncoded());
          }
      } catch(Throwable t) {
          throw new SshException("Unsupported public key type " +
                         getPublicKey().getAlgorithm(),
                         SshException.BAD_API_USAGE); // SSHException
      }

      ByteArrayWriter baw2 = new ByteArrayWriter();
      
      try {
	      // Generate the authentication request
	      baw2.writeBoolean(isAuthenticating());
	      baw2.writeString(getPublicKey().getAlgorithm());
	      baw2.writeBinaryString(encoded);
	
	      if(isAuthenticating()) {
	
	        byte[] signature;
	        if(generator != null) {
	          signature = generator.sign(getPublicKey(), baw.toByteArray());
	        }
	        else {
	          signature = getPrivateKey().sign(baw.toByteArray());
	        }
	        // Format the signature correctly
	        ByteArrayWriter sig = new ByteArrayWriter();
	        
	        try {
		        sig.writeString(getPublicKey().getAlgorithm());
		        sig.writeBinaryString(signature);
		        baw2.writeBinaryString(sig.toByteArray());
	        } finally {
	        	sig.close();
	        }
	      }
	
	      authentication.sendRequest(getUsername(),
	                                 servicename,
	                                 "publickey",
	                                 baw2.toByteArray());
	
	      // We need to read the response since we may have password change.
	      byte[] response = authentication.readMessage();
	
	      if(response[0] == SSH_MSG_USERAUTH_PK_OK) {
	        throw new AuthenticationResult(PUBLIC_KEY_ACCEPTABLE);
	      }
		authentication.transport.disconnect(TransportProtocol.PROTOCOL_ERROR,
		                                    "Unexpected message "
		                                    + response[0]
		                                    + " received");
		throw new SshException("Unexpected message "
		                       + response[0]
		                       + " received",
		                       SshException.PROTOCOL_VIOLATION);
      } finally {
    	  baw2.close();
      }
    } catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    } finally {
    	try {
			baw.close();
		} catch (IOException e) {
		}
    }


  }

  /**
   * Set the signature generator for this authentication attempt. This will
   * overide any previous configured private key.
   * @param generator
   */
  public void setSignatureGenerator(SignatureGenerator generator) {
    this.generator = generator;
  }

}
