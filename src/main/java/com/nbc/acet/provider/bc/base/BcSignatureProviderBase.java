package com.nbc.acet.provider.bc.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nbc.acet.api.AlgorithmFamily;
import com.nbc.acet.api.CryptoOperationProvider;

public abstract class BcSignatureProviderBase implements CryptoOperationProvider {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected abstract String keyAlgorithm();

    protected abstract String signatureAlgorithm();

    protected abstract AlgorithmParameterSpec keySpec();

    @Override
    public String provider() {
        return "BouncyCastle-1.84";
    }

    @Override
    public AlgorithmFamily algorithmFamily() {
        return AlgorithmFamily.SIGNATURE;
    }

    @Override
    public KeyPairResult generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm(), "BC");
        kpg.initialize(keySpec());
        KeyPair kp = kpg.generateKeyPair();
        return new KeyPairResult(
                kp.getPublic().getEncoded(),
                kp.getPrivate().getEncoded());
    }

    @Override
    public byte[] sign(byte[] message, byte[] privateKey) throws Exception {
        PrivateKey pk = KeyFactory.getInstance(keyAlgorithm(), "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Signature sig = Signature.getInstance(signatureAlgorithm(), "BC");
        sig.initSign(pk);
        sig.update(message);
        return sig.sign();
    }

    @Override
    public boolean verify(byte[] message, byte[] signature,
            byte[] publicKey) throws Exception {
        PublicKey pk = KeyFactory.getInstance(keyAlgorithm(), "BC")
                .generatePublic(new X509EncodedKeySpec(publicKey));
        Signature sig = Signature.getInstance(signatureAlgorithm(), "BC");
        sig.initVerify(pk);
        sig.update(message);
        try {
            return sig.verify(signature);
        } catch (SignatureException e) {
            return false;
        }
    }
}
