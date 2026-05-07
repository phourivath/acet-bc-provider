package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import com.nbc.acet.api.RsaParameterSet;
import com.nbc.acet.api.RsaProvider;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcRSA256Provider extends BcSignatureProviderBase implements RsaProvider {

    @Override
    public RsaParameterSet parameterSet() {
        return RsaParameterSet.RSA_2048;
    }

    @Override
    protected String keyAlgorithm() {
        return "RSA";
    }

    @Override
    protected String signatureAlgorithm() {
        return "SHA256withRSA";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
    }
}
