package com.fuzion.tools.pgp.dialoginformation;

public enum CommonDialogInformation implements IDialogInformation {
    OS_NOT_SUPPORT("Feature not supported", "This feature only work on Windows operating System"),
    ;

    private String title;
    private String message;

    CommonDialogInformation(String title, String message){
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
