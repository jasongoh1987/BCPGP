package com.fuzion.tools.pgp.ui;

public class EncryptionBean {
    private String sourceFilePath;
    private String password;

    public EncryptionBean() {
    }

    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(final String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }
}