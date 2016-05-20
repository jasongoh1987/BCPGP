package com.fuzion.tools.pgp.dialoginformation;

public enum KeyGenerationDialogInformation implements IDialogInformation {
    IDENTITY_IS_REQUIRED("Key generation fail", "Identity is required"),
    PASSWORD_IS_REQUIRED("Key generation fail", "Password is required"),
    KEY_GENERATION_SUCCESS("Success", "Key is generated successfully")
    ;

    private String title;
    private String message;

    KeyGenerationDialogInformation(String title, String message){
        this.title = title;
        this.message = message;
    }

    public String getTitle(){
        return title;
    }

    public String getMessage(){
        return message;
    }
}
