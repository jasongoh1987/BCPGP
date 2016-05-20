package com.fuzion.tools.pgp.dialoginformation;

public enum EncryptionDialogInformation implements IDialogInformation {
    FILE_FIELD_EMPTY("Invalid input", "Please select file to encrypt"),
    PASSWORD_FIELD_EMPTY("Invalid input", "Password is required"),
    ENCRYPT_SUCCESS("Success", "File is encrypted successfully")
    ;

    private String title;
    private String message;

    EncryptionDialogInformation(String title, String message){
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
