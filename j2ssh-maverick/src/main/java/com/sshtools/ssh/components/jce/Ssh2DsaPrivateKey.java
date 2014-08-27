package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshDsaPrivateKey;
import com.sshtools.ssh.components.SshDsaPublicKey;
import com.sshtools.util.SimpleASNReader;

/**
 * DSA private key implementation for the SSH2 protocol. 
 * 
 * @author Lee David Painter
 */
public class Ssh2DsaPrivateKey implements SshDsaPrivateKey {


	protected DSAPrivateKey prv;
	private Ssh2DsaPublicKey pub;

	public Ssh2DsaPrivateKey(DSAPrivateKey prv, DSAPublicKey pub) {
		this.prv = prv;
		this.pub = new Ssh2DsaPublicKey(pub);
	}

	public Ssh2DsaPrivateKey(BigInteger p,
            BigInteger q,
            BigInteger g,
            BigInteger x,
            BigInteger y) throws SshException {

		try {
			KeyFactory kf = JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_DSA)==null ? KeyFactory.getInstance(JCEAlgorithms.JCE_DSA) : KeyFactory.getInstance(JCEAlgorithms.JCE_DSA, JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_DSA));
			DSAPrivateKeySpec spec = new DSAPrivateKeySpec(x,p,q,g);
			prv = (DSAPrivateKey) kf.generatePrivate(spec);

			pub = new Ssh2DsaPublicKey(p, q, g, y);
		} catch (Throwable e) {
			throw new SshException(e);
		}

	}

	public byte[] sign(byte[] data) throws IOException {
		try {
			Signature l_sig = JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithDSA) == null ? Signature.getInstance(JCEAlgorithms.JCE_SHA1WithDSA) : Signature.getInstance(JCEAlgorithms.JCE_SHA1WithDSA, JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithDSA));
			l_sig.initSign(prv);
			l_sig.update(data);

            byte[] signature = l_sig.sign();
            
            SimpleASNReader asn = new SimpleASNReader(signature);
            asn.getByte();
            asn.getLength();
            asn.getByte();

            byte[] r = asn.getData();
            asn.getByte();

            byte[] s = asn.getData();

            byte[] decoded = null;
            int numSize = 32;
            if(r.length < numSize) {
            	numSize = 28;
            	if(r.length < numSize) {
            		numSize = 20;
            	}
            } 

            decoded = new byte[numSize*2];
        	if (r.length >= numSize) {
                System.arraycopy(r, r.length - numSize, decoded, 0, numSize);
             } else {
                System.arraycopy(r, 0, decoded, numSize - r.length, r.length);
             }

             if (s.length >= numSize) {
                 System.arraycopy(s, s.length - numSize, decoded, numSize, numSize);
             } else {
                 System.arraycopy(s, 0, decoded, numSize + (numSize - s.length), s.length);
             }

            return decoded;
		} catch (Exception e) {
			throw new IOException("Failed to sign data! " + e.getMessage());
		}

	}

	public String getAlgorithm() {
		return "ssh-dss";
	}

	public SshDsaPublicKey getPublicKey() {
		return pub;
	}

	public BigInteger getX() {
		return prv.getX();
	}

}
