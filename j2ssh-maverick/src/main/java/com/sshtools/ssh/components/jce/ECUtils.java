package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class ECUtils {

	public static byte[] toByteArray(ECPoint e, EllipticCurve curve) {
		byte[] x = e.getAffineX().toByteArray();
		byte[] y = e.getAffineY().toByteArray();
		int i, xoff = 0, yoff = 0;
		for (i = 0; i < x.length - 1; i++)
			if (x[i] != 0) {
				xoff = i;
				break;
			}
		for (i = 0; i < y.length - 1; i++)
			if (y[i] != 0) {
				yoff = i;
				break;
			}
		int len = (curve.getField().getFieldSize() + 7) / 8;
		if ((x.length - xoff) > len || (y.length - yoff) > len)
			return null;
		byte[] ret = new byte[len * 2 + 1];
		ret[0] = 4;
		System.arraycopy(x, xoff, ret, 1 + len - (x.length - xoff), x.length
				- xoff);
		System.arraycopy(y, yoff, ret, ret.length - (y.length - yoff), y.length
				- yoff);
		return ret;
	}

	public static ECPoint fromByteArray(byte[] b, EllipticCurve curve) {
		int len = (curve.getField().getFieldSize() + 7) / 8;
		if (b.length != 2 * len + 1 || b[0] != 4)
			return null;
		byte[] x = new byte[len];
		byte[] y = new byte[len];
		System.arraycopy(b, 1, x, 0, len);
		System.arraycopy(b, len + 1, y, 0, len);
		return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
	}

	private static byte[] createHeadForNamedCurve(String name, int size)
	        throws NoSuchAlgorithmException,
	        InvalidAlgorithmParameterException, IOException {
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
	    ECGenParameterSpec m = new ECGenParameterSpec(name);
	    kpg.initialize(m);
	    KeyPair kp = kpg.generateKeyPair();
	    byte[] encoded = kp.getPublic().getEncoded();
	    return Arrays.copyOf(encoded, (encoded.length - 2 * (size / Byte.SIZE)) -1);
	}
	
	public static ECPublicKey convertKey(byte[] w, byte[] HEAD) throws InvalidKeySpecException {
	    byte[] encodedKey = new byte[HEAD.length + w.length];
	    System.arraycopy(HEAD, 0, encodedKey, 0, HEAD.length);
	    System.arraycopy(w, 0, encodedKey, HEAD.length, w.length);
	    KeyFactory eckf;
	    try {
	        eckf = KeyFactory.getInstance("EC");
	    } catch (NoSuchAlgorithmException e) {
	        throw new IllegalStateException("EC key factory not present in runtime");
	    }
	    X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
	    return (ECPublicKey) eckf.generatePublic(ecpks);
	}

	public static int getCurveSize(String curve) throws IOException {
		if (curve.contains("prime256v1") || curve.contains("secp256r1")) {
			return 256;
		} else if (curve.contains("secp384r1")) {
			return 384;
		} else if (curve.contains("secp521r1")) {
			return 521;
		} else {
			throw new IOException("Unsupported curve name " + curve);
		}
	}
	
	public static ECPublicKey decodeKey(byte[] encoded, String namedCurve) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException { 
		return convertKey(encoded, createHeadForNamedCurve(namedCurve, getCurveSize(namedCurve)));
	}
	
}
