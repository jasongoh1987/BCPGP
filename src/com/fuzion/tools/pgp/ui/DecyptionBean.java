package com.fuzion.tools.pgp.ui;

public class DecyptionBean {
    private String password;
    private String sourceFilePath;

    public DecyptionBean() {
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(final String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }
}