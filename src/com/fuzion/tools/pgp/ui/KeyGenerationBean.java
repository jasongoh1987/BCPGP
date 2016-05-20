package com.fuzion.tools.pgp.ui;

public class KeyGenerationBean {
    private String keyGenerationID;
    private String keyGenerationPassword;

    public KeyGenerationBean() {
    }

    public String getKeyGenerationID() {
        return keyGenerationID;
    }

    public void setKeyGenerationID(final String keyGenerationID) {
        this.keyGenerationID = keyGenerationID;
    }

    public String getKeyGenerationPassword() {
        return keyGenerationPassword;
    }

    public void setKeyGenerationPassword(final String keyGenerationPassword) {
        this.keyGenerationPassword = keyGenerationPassword;
    }
}