package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

import com.nbc.acet.api.SlhDsaParameterSet;
import com.nbc.acet.api.SlhDsaProvider;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcSLHDSASHA2192SProvider extends BcSignatureProviderBase implements SlhDsaProvider {

    @Override
    public SlhDsaParameterSet parameterSet() {
        return SlhDsaParameterSet.SLH_DSA_SHA2_192S;
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

    @Override
    protected boolean signatureSupportsContext() {
        return true;
    }
}
