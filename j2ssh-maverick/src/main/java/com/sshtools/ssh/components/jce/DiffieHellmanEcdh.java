package com.sshtools.ssh.components.jce;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import com.sshtools.logging.Logger;
import com.sshtools.logging.LoggerFactory;
import com.sshtools.logging.LoggerLevel;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.Digest;
import com.sshtools.ssh.components.SshKeyExchange;
import com.sshtools.ssh.components.SshKeyExchangeClient;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

public class DiffieHellmanEcdh extends SshKeyExchangeClient implements
		SshKeyExchange {

	public static final int SSH_MSG_KEX_ECDH_INIT = 30;
	public static final int SSH_MSG_KEX_ECDH_REPLY = 31;
	
	String name;
	String curve;
	
	byte[] Q_S;
	byte[] Q_C;
	
	String clientId;
	String serverId;
	byte[] clientKexInit;
	byte[] serverKexInit;
	  
	protected DiffieHellmanEcdh(String name, String curve, String hashAlgorithm) {
		super(hashAlgorithm);
		this.name = name;
		this.curve = curve;
	}
	
	@Override
	public String getAlgorithm() {
		return name;
	}

	@Override
	public void performClientExchange(String clientId, String serverId,
			byte[] clientKexInit, byte[] serverKexInit) throws SshException {
	    
		this.clientId = clientId;
	    this.serverId = serverId;
	    this.clientKexInit = clientKexInit;
	    this.serverKexInit = serverKexInit;
		
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH");
			ECGenParameterSpec namedSpec = new ECGenParameterSpec(curve);
			keyGen.initialize(namedSpec, new SecureRandom());

			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			KeyPair keyPair = keyGen.generateKeyPair();
			keyAgreement.init(keyPair.getPrivate());
			
			ECPublicKey ec = (ECPublicKey) keyPair.getPublic();
			ByteArrayWriter msg = new ByteArrayWriter();
			Q_C = ECUtils.toByteArray(ec.getW(), ec.getParams().getCurve());
			
			try {
				msg.write(SSH_MSG_KEX_ECDH_INIT);
				msg.writeBinaryString(Q_C);
		        if(LoggerFactory.getInstance().isLevelEnabled(LoggerLevel.DEBUG)) {
		        	LoggerFactory.getInstance().log(LoggerLevel.DEBUG, this, "Sending SSH_MSG_KEX_ECDH_INIT");
		        }
				transport.sendMessage(msg.toByteArray(), true);
			} finally {
				msg.close();
			}
			
			byte[] resp = transport.nextMessage();
			
			if(resp[0]!=SSH_MSG_KEX_ECDH_REPLY) {
				throw new SshException("Expected SSH_MSG_KEX_ECDH_REPLY but got message id " + resp[0], SshException.KEY_EXCHANGE_FAILED);
			}
			ByteArrayReader reply = new ByteArrayReader(resp, 1, resp.length-1);
			
			try {
				hostKey = reply.readBinaryString();
				Q_S = reply.readBinaryString();
				signature = reply.readBinaryString();
				
				keyAgreement.doPhase(ECUtils.decodeKey(Q_S, curve), true);
				
				byte[] tmp = keyAgreement.generateSecret();
		        if((tmp[0] & 0x80)==0x80) {
		        	byte[] tmp2 = new byte[tmp.length+1];
		        	System.arraycopy(tmp, 0, tmp2, 1, tmp.length);
		        	tmp = tmp2;
		        }
		        
		        // Calculate diffe hellman k value
		        secret = new BigInteger(tmp);
			} finally {
				reply.close();
			}

			calculateExchangeHash();
		} catch (Exception e) {
			throw new SshException("Failed to process key exchange",
                    SshException.INTERNAL_ERROR, e);
		}
	}

	@Override
	public boolean isKeyExchangeMessage(int messageid) {
		switch(messageid) {
		case SSH_MSG_KEX_ECDH_INIT:
		case SSH_MSG_KEX_ECDH_REPLY:
			return true;
		}
		return false;
	}

	protected void calculateExchangeHash() throws SshException {
		Digest hash = (Digest) ComponentManager.getInstance()
				.supportedDigests().getInstance(getHashAlgorithm());

		// The local software version comments
		hash.putString(clientId);

		// The remote software version comments
		hash.putString(serverId);

		// The local kex init payload
		hash.putInt(clientKexInit.length);
		hash.putBytes(clientKexInit);

		// The remote kex init payload
		hash.putInt(serverKexInit.length);
		hash.putBytes(serverKexInit);

		// The host key
		hash.putInt(hostKey.length);
		hash.putBytes(hostKey);

		hash.putInt(Q_C.length);
		hash.putBytes(Q_C);
		
		hash.putInt(Q_S.length);
		hash.putBytes(Q_S);

		// The diffie hellman k value
		hash.putBigInteger(secret);

		// Do the final output
		exchangeHash = hash.doFinal();
	}
}
