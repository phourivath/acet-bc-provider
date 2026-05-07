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
import org.bouncycastle.jcajce.spec.ContextParameterSpec;

import com.nbc.acet.api.CryptoOperationProvider.KeyPairResult;

public abstract class BcSignatureProviderBase {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected abstract String keyAlgorithm();

    protected abstract String signatureAlgorithm();

    protected abstract AlgorithmParameterSpec keySpec();

    protected boolean signatureSupportsContext() {
        return false;
    }

    public String provider() {
        return "BouncyCastle-1.84";
    }

    public KeyPairResult generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm(), "BC");
        kpg.initialize(keySpec());
        KeyPair kp = kpg.generateKeyPair();
        return new KeyPairResult(
                kp.getPublic().getEncoded(),
                kp.getPrivate().getEncoded());
    }

    public byte[] sign(byte[] message, byte[] privateKey) throws Exception {
        PrivateKey pk = KeyFactory.getInstance(keyAlgorithm(), "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Signature sig = Signature.getInstance(signatureAlgorithm(), "BC");
        sig.initSign(pk);
        sig.update(message);
        return sig.sign();
    }

    public byte[] sign(byte[] message, byte[] privateKey, byte[] context) throws Exception {
        if ((context == null || context.length == 0) && !signatureSupportsContext()) {
            return sign(message, privateKey);
        }
        if (context != null && context.length > 0 && !signatureSupportsContext()) {
            throw new UnsupportedOperationException(
                    provider() + " does not support sign() with context");
        }

        PrivateKey pk = KeyFactory.getInstance(keyAlgorithm(), "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Signature sig = Signature.getInstance(signatureAlgorithm(), "BC");
        sig.initSign(pk);
        if (signatureSupportsContext()) {
            sig.setParameter(new ContextParameterSpec(context != null ? context : new byte[0]));
        }
        sig.update(message);
        return sig.sign();
    }

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

    public boolean verify(byte[] message, byte[] signature,
            byte[] publicKey, byte[] context) throws Exception {
        if ((context == null || context.length == 0) && !signatureSupportsContext()) {
            return verify(message, signature, publicKey);
        }
        if (context != null && context.length > 0 && !signatureSupportsContext()) {
            throw new UnsupportedOperationException(
                    provider() + " does not support verify() with context");
        }

        PublicKey pk = KeyFactory.getInstance(keyAlgorithm(), "BC")
                .generatePublic(new X509EncodedKeySpec(publicKey));
        Signature sig = Signature.getInstance(signatureAlgorithm(), "BC");
        sig.initVerify(pk);
        if (signatureSupportsContext()) {
            sig.setParameter(new ContextParameterSpec(context != null ? context : new byte[0]));
        }
        sig.update(message);
        try {
            return sig.verify(signature);
        } catch (SignatureException e) {
            return false;
        }
    }

    public boolean supportsContext() {
        return signatureSupportsContext();
    }
}
