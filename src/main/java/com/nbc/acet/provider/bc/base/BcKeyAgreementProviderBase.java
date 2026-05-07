package com.nbc.acet.provider.bc.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nbc.acet.api.CryptoOperationProvider.KeyPairResult;

public abstract class BcKeyAgreementProviderBase {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected abstract String keyAlgorithm();

    protected abstract String agreementAlgorithm();

    protected abstract AlgorithmParameterSpec keySpec();

    public String provider() {
        return "BouncyCastle-1.84";
    }

    public KeyPairResult generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm(), "BC");
        AlgorithmParameterSpec spec = keySpec();
        if (spec != null) {
            kpg.initialize(spec);
        }
        KeyPair kp = kpg.generateKeyPair();
        return new KeyPairResult(
                kp.getPublic().getEncoded(),
                kp.getPrivate().getEncoded());
    }

    public byte[] agree(byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm(), "BC");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(myPrivateKey));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(theirPublicKey));
        KeyAgreement ka = KeyAgreement.getInstance(agreementAlgorithm(), "BC");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }
}
