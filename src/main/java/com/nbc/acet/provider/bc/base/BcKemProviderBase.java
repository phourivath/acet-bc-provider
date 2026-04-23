package com.nbc.acet.provider.bc.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nbc.acet.api.AlgorithmFamily;
import com.nbc.acet.api.CryptoOperationProvider;

public abstract class BcKemProviderBase implements CryptoOperationProvider {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected abstract String kemAlgorithm();

    protected abstract AlgorithmParameterSpec kemSpec();

    @Override
    public String provider() {
        return "BouncyCastle-1.84";
    }

    @Override
    public AlgorithmFamily algorithmFamily() {
        return AlgorithmFamily.KEM;
    }

    @Override
    public KeyPairResult generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(kemAlgorithm(), "BC");
        
        // Only initialize if a spec is actually provided
        // X25519MLKEM786 doesn't need kemSpec
        AlgorithmParameterSpec spec = kemSpec();
        if (spec != null) {
            kpg.initialize(spec);
        }
        
        KeyPair kp = kpg.generateKeyPair();
        return new KeyPairResult(
                kp.getPublic().getEncoded(),
                kp.getPrivate().getEncoded());
    }

    @Override
    public EncapsulationResult encapsulate(byte[] publicKey) throws Exception {
        java.security.PublicKey pub = KeyFactory.getInstance(kemAlgorithm(), "BC")
                .generatePublic(new X509EncodedKeySpec(publicKey));

        KeyGenerator keyGen = KeyGenerator.getInstance(kemAlgorithm(), "BC");
        // withNoKdf(): bypass default KDF-3/SHA-256 to return raw FIPS 203 shared secret K
        keyGen.init(new KEMGenerateSpec.Builder(pub, "Secret", 256).withNoKdf().build());
        SecretKeyWithEncapsulation encapsulated =
                (SecretKeyWithEncapsulation) keyGen.generateKey();

        return new EncapsulationResult(
                encapsulated.getEncoded(),
                encapsulated.getEncapsulation());
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation, byte[] privateKey) throws Exception {
        java.security.PrivateKey priv = KeyFactory.getInstance(kemAlgorithm(), "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        KeyGenerator keyGen = KeyGenerator.getInstance(kemAlgorithm(), "BC");
        // withNoKdf(): bypass default KDF-3/SHA-256 to return raw FIPS 203 shared secret K
        keyGen.init(new KEMExtractSpec.Builder(priv, encapsulation, "Secret", 256).withNoKdf().build());
        SecretKey secret = keyGen.generateKey();

        return secret.getEncoded();
    }
}
