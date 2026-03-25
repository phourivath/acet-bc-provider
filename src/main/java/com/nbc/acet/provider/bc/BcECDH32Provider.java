package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import com.nbc.acet.api.Algorithm;
import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcKeyAgreementProviderBase;

public class BcECDH32Provider extends BcKeyAgreementProviderBase {

    @Override
    public Algorithm algorithm() {
        return Algorithm.ECDH;
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.X25519;
    }

    @Override
    protected String keyAlgorithm() {
        return "X25519";
    }

    @Override
    protected String agreementAlgorithm() {
        return "X25519";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return null;
    }
}
