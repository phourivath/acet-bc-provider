package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.nbc.acet.api.EcdsaParameterSet;
import com.nbc.acet.api.EcdsaProvider;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcECDSA32Provider extends BcSignatureProviderBase implements EcdsaProvider {

    @Override
    public EcdsaParameterSet parameterSet() {
        return EcdsaParameterSet.ECDSA_P256;
    }

    @Override
    protected String keyAlgorithm() {
        return "EC";
    }

    @Override
    protected String signatureAlgorithm() {
        return "SHA256withECDSA";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return ECNamedCurveTable.getParameterSpec("P-256");
    }
}
