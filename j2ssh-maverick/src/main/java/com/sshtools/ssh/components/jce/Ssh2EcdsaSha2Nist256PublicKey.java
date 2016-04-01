package com.sshtools.ssh.components.jce;


public class Ssh2EcdsaSha2Nist256PublicKey extends Ssh2EcdsaSha2NistPublicKey {

	public Ssh2EcdsaSha2Nist256PublicKey() {
		super("ecdsa-sha2-nistp256", "SHA256/ECDSA", "secp256r1");
	}
}
