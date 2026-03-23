package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcSlhDsaSha2192SProvider extends BcSignatureProviderBase {

    @Override
    public String algorithm() {
        return "SLH-DSA";
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.SLH_DSA_SHA2_192S;
    }

    @Override
    protected String keyAlgorithm() {
        return "SLH-DSA";
    }

    @Override
    protected String signatureAlgorithm() {
        return "SLH-DSA-SHA2-192s";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return SLHDSAParameterSpec.slh_dsa_sha2_192s;
    }
}
