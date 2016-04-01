package com.sshtools.ssh.components.jce;


public class Ssh2EcdsaSha2Nist521PublicKey extends Ssh2EcdsaSha2NistPublicKey {

	public Ssh2EcdsaSha2Nist521PublicKey() {
		super("ecdsa-sha2-nistp521", "SHA512/ECDSA", "secp521r1");
	}
}
