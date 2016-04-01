package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

import com.sshtools.ssh.components.SshPrivateKey;
import com.sshtools.util.ByteArrayWriter;
import com.sshtools.util.SimpleASNReader;

public class Ssh2EcdsaSha2NistPrivateKey implements SshPrivateKey {

	String name;
	String spec;
	String curve;
	
	ECPrivateKey prv;
	
	public Ssh2EcdsaSha2NistPrivateKey(ECPrivateKey prv) throws IOException {
        this.prv = prv;
        String curve = prv.getParams().toString();
    	if(curve.contains("prime256v1") || curve.contains("secp256r1")) {
    		this.curve = "secp256r1";
    		this.name = "ecdsa-sha2-nistp256";
    		this.spec = "SHA256/ECDSA";
    	} else if(curve.contains("secp384r1")) {
    		this.curve = "secp384r1";
    		this.name = "ecdsa-sha2-nistp384";
    		this.spec = "SHA384/ECDSA";        		
    	} else if(curve.contains("secp521r1")) {
    		this.curve = "secp521r1";
    		this.name = "ecdsa-sha2-nistp521";
    		this.spec = "SHA512/ECDSA";
    	} else {
    		throw new IOException("Unsupported curve name " + curve);
    	}
	}
	
	public byte[] sign(byte[] data) throws IOException {
		try {
			Signature sig = JCEProvider.getProviderForAlgorithm(spec) == null ? Signature.getInstance(spec) : Signature.getInstance(spec, JCEProvider.getProviderForAlgorithm(spec));
            sig.initSign(prv);
            sig.update(data);
            byte[] sigRaw = sig.sign();
            ByteArrayWriter baw = new ByteArrayWriter();
            try {
                SimpleASNReader asn = new SimpleASNReader(sigRaw);
                
                asn.getByte();
                asn.getLength();
                asn.getByte();

                byte[] r = asn.getData();
                asn.getByte();

                byte[] s = asn.getData();

                baw.writeBinaryString(r);
                baw.writeBinaryString(s);
                return baw.toByteArray();
            } catch (IOException ioe) {
                throw new IOException("DER decode failed: " + ioe.getMessage());
            } finally {
            	baw.close();
            }
        } catch (Exception e) {
            throw new IOException("Error in " + name +
                                             " sign: " + e.getMessage());
        }

	}

	public String getAlgorithm() {
		return name;
	}

	public PrivateKey getJCEPrivateKey() {
		return prv;
	}

}
