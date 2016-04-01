package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshKeyFingerprint;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;
import com.sshtools.util.SimpleASNWriter;

public class Ssh2EcdsaSha2NistPublicKey implements SshPublicKey {

	String name;
	String spec;
	String curve;

	protected ECPublicKey pub;

	public Ssh2EcdsaSha2NistPublicKey(ECPublicKey pub) throws IOException {
		this.pub = pub;
		String curve = pub.getParams().toString();
		if (curve.contains("prime256v1") || curve.contains("secp256r1")) {
			this.curve = "secp256r1";
			this.name = "ecdsa-sha2-nistp256";
			this.spec = "SHA256/ECDSA";
		} else if (curve.contains("secp384r1")) {
			this.curve = "secp384r1";
			this.name = "ecdsa-sha2-nistp384";
			this.spec = "SHA384/ECDSA";
		} else if (curve.contains("secp521r1")) {
			this.curve = "secp521r1";
			this.name = "ecdsa-sha2-nistp521";
			this.spec = "SHA512/ECDSA";
		} else {
			throw new IOException("Unsupported curve name " + curve);
		}
	}

	Ssh2EcdsaSha2NistPublicKey(String name, String spec, String curve) {
		this.name = name;
		this.spec = spec;
		this.curve = curve;
	}

	public void init(byte[] blob, int start, int len) throws SshException {

		ByteArrayReader buf = new ByteArrayReader(blob, start, len);
		try {

			@SuppressWarnings("unused")
			String type = buf.readString();

			buf.readString();
			byte[] Q = buf.readBinaryString();

			ECParameterSpec ecspec = getCurveParams(curve);

			ECPoint p = ECUtils.fromByteArray(Q, ecspec.getCurve());
			KeyFactory keyFactory = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_EC) == null ? KeyFactory
					.getInstance(JCEAlgorithms.JCE_EC) : KeyFactory
					.getInstance(JCEAlgorithms.JCE_EC, JCEProvider
							.getProviderForAlgorithm(JCEAlgorithms.JCE_EC));
			pub = (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(
					p, ecspec));
		} catch (Throwable t) {
			t.printStackTrace();
			throw new SshException("Failed to decode public key blob",
					SshException.INTERNAL_ERROR);
		} finally {
			try {
				buf.close();
			} catch (IOException e) {
			}
		}

	}

	public String getAlgorithm() {
		return name;
	}

	public int getBitLength() {
		return pub.getParams().getOrder().bitLength();
	}

	public byte[] getEncoded() throws SshException {

		ByteArrayWriter blob = new ByteArrayWriter();

		try {

			blob.writeString(name);
			blob.writeString(name.substring(name.lastIndexOf("-") + 1));
			blob.writeBinaryString(getPublicOctet());
			return blob.toByteArray();
		} catch (Throwable t) {
			throw new SshException("Failed to encode public key",
					SshException.INTERNAL_ERROR);
		} finally {
			try {
				blob.close();
			} catch (IOException e) {
			}
		}

	}

	public byte[] getPublicOctet() {
		return ECUtils.toByteArray(pub.getW(), pub.getParams()
				.getCurve());
	}

	public String getFingerprint() throws SshException {
		return SshKeyFingerprint.getFingerprint(getEncoded());
	}

	public boolean verifySignature(byte[] signature, byte[] data)
			throws SshException {

		ByteArrayReader bar = new ByteArrayReader(signature);
		try {

			int len = (int) bar.readInt();
			// Check for differing version of the transport protocol
			if (bar.available() > len) {

				byte[] sig = new byte[len];
				bar.read(sig);

				// log.debug("Signature blob is " + new String(sig));
				String header = new String(sig);

				if (!header.equals(name)) {
					throw new SshException(
							"The encoded signature is not ECDSA",
							SshException.INTERNAL_ERROR);
				}

				signature = bar.readBinaryString();
			}

			// Using a SimpleASNWriter

			bar.close();

			bar = new ByteArrayReader(signature);
			BigInteger r = bar.readBigInteger();
			BigInteger s = bar.readBigInteger();

			SimpleASNWriter asn = new SimpleASNWriter();
			asn.writeByte(0x02);
			asn.writeData(r.toByteArray());
			asn.writeByte(0x02);
			asn.writeData(s.toByteArray());

			SimpleASNWriter asnEncoded = new SimpleASNWriter();
			asnEncoded.writeByte(0x30);
			asnEncoded.writeData(asn.toByteArray());

			byte[] encoded = asnEncoded.toByteArray();

			Signature sig = JCEProvider.getProviderForAlgorithm(spec) == null ? Signature
					.getInstance(spec) : Signature.getInstance(spec,
					JCEProvider.getProviderForAlgorithm(spec));
			sig.initVerify(pub);
			sig.update(data);

			return sig.verify(encoded);
		} catch (Exception ex) {
			throw new SshException(SshException.JCE_ERROR, ex);
		} finally {
			try {
				bar.close();
			} catch (IOException e) {
			}
		}

	}

	public ECParameterSpec getCurveParams(String curve) {
		try {
			KeyPairGenerator gen = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_EC) == null ? KeyPairGenerator
					.getInstance(JCEAlgorithms.JCE_EC) : KeyPairGenerator
					.getInstance(JCEAlgorithms.JCE_EC, JCEProvider
							.getProviderForAlgorithm(JCEAlgorithms.JCE_EC));

			gen.initialize(new ECGenParameterSpec(curve),
					JCEProvider.getSecureRandom());
			KeyPair tmp = gen.generateKeyPair();
			return ((ECPublicKey) tmp.getPublic()).getParams();
		} catch (Throwable t) {
		}
		return null;
	}



	public PublicKey getJCEPublicKey() {
		return pub;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((pub == null) ? 0 : pub.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Ssh2EcdsaSha2NistPublicKey other = (Ssh2EcdsaSha2NistPublicKey) obj;
		if (pub == null) {
			if (other.pub != null)
				return false;
		} else if (!pub.equals(other.pub))
			return false;
		return true;
	}
	
	public static void main(String[] args) throws Exception {
		
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
	    ECGenParameterSpec gps = new ECGenParameterSpec ("secp256r1"); // NIST P-256 
	    kpg.initialize(gps); 
	    KeyPair apair = kpg.generateKeyPair(); 
	    ECPublicKey apub  = (ECPublicKey)apair.getPublic();
	    ECParameterSpec aspec = apub.getParams();
	    // could serialize aspec for later use (in compatible JRE)
	    //
	    // for test only reuse bogus pubkey, for real substitute values 
	    ECPoint apoint = apub.getW();
	    BigInteger x = apoint.getAffineX(), y = apoint.getAffineY();
	    // construct point plus params to pubkey
	    ECPoint bpoint = new ECPoint (x,y); 
	    ECPublicKeySpec bpubs = new ECPublicKeySpec (bpoint, aspec);
	    KeyFactory kfa = KeyFactory.getInstance ("EC");
	    ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
	    
	    new Ssh2EcdsaSha2NistPublicKey(bpub);
	}

}
