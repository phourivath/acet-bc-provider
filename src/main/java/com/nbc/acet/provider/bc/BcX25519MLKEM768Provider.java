package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import com.nbc.acet.api.X25519MlKemParameterSet;
import com.nbc.acet.api.X25519MlKemProvider;
import com.nbc.acet.provider.bc.base.BcKemProviderBase;

public class BcX25519MLKEM768Provider extends BcKemProviderBase implements X25519MlKemProvider {

    @Override
    public X25519MlKemParameterSet parameterSet() {
        return X25519MlKemParameterSet.X25519MLKEM768;
    }

    @Override
    protected String kemAlgorithm() {
        return "X25519-MLKEM768"; 
    }

    @Override
    protected AlgorithmParameterSpec kemSpec() {
        return null;
    }
}
