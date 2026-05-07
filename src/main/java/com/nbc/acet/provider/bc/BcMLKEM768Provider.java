package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import com.nbc.acet.api.MlKemParameterSet;
import com.nbc.acet.api.MlKemProvider;
import com.nbc.acet.provider.bc.base.BcKemProviderBase;

public class BcMLKEM768Provider extends BcKemProviderBase implements MlKemProvider {

    @Override
    public MlKemParameterSet parameterSet() {
        return MlKemParameterSet.ML_KEM_768;
    }

    @Override
    protected String kemAlgorithm() {
        return "ML-KEM";
    }

    @Override
    protected AlgorithmParameterSpec kemSpec() {
        return MLKEMParameterSpec.ml_kem_768;
    }
}
