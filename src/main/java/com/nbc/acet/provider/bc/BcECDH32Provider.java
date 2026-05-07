package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import com.nbc.acet.api.EcdhParameterSet;
import com.nbc.acet.api.EcdhProvider;
import com.nbc.acet.provider.bc.base.BcKeyAgreementProviderBase;

public class BcECDH32Provider extends BcKeyAgreementProviderBase implements EcdhProvider {

    @Override
    public EcdhParameterSet parameterSet() {
        return EcdhParameterSet.X25519;
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
