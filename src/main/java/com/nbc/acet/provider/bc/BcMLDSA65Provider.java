package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import com.nbc.acet.api.MlDsaParameterSet;
import com.nbc.acet.api.MlDsaProvider;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcMLDSA65Provider extends BcSignatureProviderBase implements MlDsaProvider {

    @Override
    public MlDsaParameterSet parameterSet() {
        return MlDsaParameterSet.ML_DSA_65;
    }

    @Override
    protected String keyAlgorithm() {
        return "ML-DSA";
    }

    @Override
    protected String signatureAlgorithm() {
        return "ML-DSA-65";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return MLDSAParameterSpec.ml_dsa_65;
    }

    @Override
    protected boolean signatureSupportsContext() {
        return true;
    }
}
