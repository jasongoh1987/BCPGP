package com.fuzion.tools.pgp.dialoginformation;

public enum DecryptionDialogInformation implements IDialogInformation {
    FILE_FIELD_EMPTY("Invalid input", "Please select file to decrypt"),
    PASSWORD_FIELD_EMPTY("Invalid input", "Password is required"),
    DECRYPT_SUCCESS("Success", "File is decrypted successfully")
    ;

    private String title;
    private String message;

    DecryptionDialogInformation(String title, String message){
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
