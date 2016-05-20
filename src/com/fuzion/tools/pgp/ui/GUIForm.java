package com.fuzion.tools.pgp.ui;

import com.fuzion.tools.pgp.BCPGPDecryptor;
import com.fuzion.tools.pgp.BCPGPEncryptor;
import com.fuzion.tools.pgp.BCPGPKeyGenTools;
import com.fuzion.tools.pgp.dialoginformation.*;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;
import java.util.List;

public class GUIForm {
    private JPanel panel1;
    private JButton keyGenerateButton;
    private JTextField keyGenIdField;
    private JPasswordField keyGenPasswordField;
    private JTextField encryptFilePathField;
    private JPasswordField encryptPasswordField;
    private JButton encryptButton;
    private JTextField decryptFilePathField;
    private JPasswordField decryptPasswordField;
    private JButton decryptButton;
    private JButton encryptFileChooseButton;
    private JButton decryptFileChooseButton;
    private JRadioButton encryptionRadioButton;
    private JRadioButton decryptionRadioButton;
    private JButton encryptOpenFolderButton;
    private JButton decryptOpenFileButton;
    private JTextField encryptedPathTextField;
    private JTextField decryptedPathTextField;
    private JFrame frame;

    private JFileChooser fc = new JFileChooser();

    private static final String APPLICATION_NAME = "HLB Direct Debit Encrpytion Tool";
    private static final String PUB_KEY_PATH = "keys/hlb_pub.key";
    private static final String PRIVATE_KEY_PATH = "keys/sec.key";
    private static final String ENCRYPTION_EXT = ".enc";
    private static final String DECRYPT_DIR = "decrypted";
    private static final String ENCRYPT_DIR = "encrypted";

    private String keysDir = System.getProperty("user.dir") + File.separator + "keys";
    private File secKeyFile = new File(keysDir + File.separator + "sec.key");
    private File pubKeyFile = new File(keysDir + File.separator + "pub.key");

    private String encryptedFilePath;
    private String decryptedFilePath;

    public GUIForm() {
        keyGenerateButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (keyGenerateButton.isEnabled()) {
                    super.mouseReleased(e);
                    if (keyGenIdField.getText().trim().length() == 0) {
                        showErrorDialog(KeyGenerationDialogInformation.IDENTITY_IS_REQUIRED);
                    } else if (keyGenPasswordField.getPassword().length == 0) {
                        showErrorDialog(KeyGenerationDialogInformation.PASSWORD_IS_REQUIRED);
                    } else {
                        try {
                            keyGeneration(keyGenIdField.getText(), keyGenPasswordField.getPassword());
                            showInformationDialog(KeyGenerationDialogInformation.KEY_GENERATION_SUCCESS);
                            showKeyGenMenu(GUIForm.this);
                            showEncryptMenu(GUIForm.this);
                            showDecryptMenu(GUIForm.this);
                            enableEncryption();
                        } catch (Exception ex) {
                            showExceptionDialog(ex);
                        }
                    }
                }
            }
        });

        encryptButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (encryptButton.isEnabled()) {
                    super.mouseReleased(e);
                    validateAndEncrypt();
                }
            }
        });

        decryptButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (decryptButton.isEnabled()) {
                    super.mouseReleased(e);
                    validateAndDecrypt();
                }
            }
        });

        encryptFileChooseButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (encryptFileChooseButton.isEnabled()) {
                    super.mouseReleased(e);
                    int retval = fc.showOpenDialog(encryptFileChooseButton.getParent().getParent());
                    if (retval == JFileChooser.APPROVE_OPTION) {
                        File file = fc.getSelectedFile();
                        encryptFilePathField.setText(file.getAbsolutePath());
                    }
                }
            }
        });

        decryptFileChooseButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (decryptFileChooseButton.isEnabled()) {
                    super.mouseClicked(e);
                    int retval = fc.showOpenDialog(decryptFileChooseButton.getParent().getParent());
                    if (retval == JFileChooser.APPROVE_OPTION) {
                        File file = fc.getSelectedFile();
                        decryptFilePathField.setText(file.getAbsolutePath());
                    }
                }
            }
        });

        encryptionRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                enableEncryption();
            }
        });

        decryptionRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                enableDecryption();
            }
        });

        encryptOpenFolderButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                super.mouseReleased(e);
                File encryptedFile = new File(encryptedFilePath);
                File encryptedFolder = new File(encryptedFile.getParent());
                Runtime rt = Runtime.getRuntime();
                try {
                    rt.exec("cmd /c start \"\" \"" + encryptedFolder.getAbsolutePath() + "\"");
                } catch (IOException e1) {
                    e1.printStackTrace();
                    showErrorDialog(CommonDialogInformation.OS_NOT_SUPPORT);
                }
            }
        });

        decryptOpenFileButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                super.mouseReleased(e);
                Runtime rt = Runtime.getRuntime();
                try {
                    rt.exec("cmd /c start \"\" \"" + decryptedFilePath + "\"");
                } catch (IOException e1) {
                    e1.printStackTrace();
                    showErrorDialog(CommonDialogInformation.OS_NOT_SUPPORT);
                }
            }
        });

        encryptPasswordField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (encryptPasswordField.isEnabled()) {
                    super.keyReleased(e);
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        validateAndEncrypt();
                    }
                }
            }
        });

        decryptPasswordField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (decryptPasswordField.isEnabled()) {
                    super.keyReleased(e);
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        validateAndDecrypt();
                    }
                }
            }
        });
    }

    private void validateAndEncrypt() {
        if (encryptFilePathField.getText().trim().length() == 0) {
            showErrorDialog(EncryptionDialogInformation.FILE_FIELD_EMPTY);
        } else if (encryptPasswordField.getPassword().length == 0) {
            showErrorDialog(EncryptionDialogInformation.PASSWORD_FIELD_EMPTY);
        } else {
            try {
                encrypt(encryptFilePathField.getText(), encryptPasswordField.getPassword());
                showInformationDialog(EncryptionDialogInformation.ENCRYPT_SUCCESS);
                validateEncryptedPathAndMenu();
            } catch (Exception ex) {
                showExceptionDialog(ex);
            }
        }
    }

    private void validateAndDecrypt() {
        if (decryptFilePathField.getText().trim().length() == 0) {
            showErrorDialog(DecryptionDialogInformation.FILE_FIELD_EMPTY);
        } else if (decryptPasswordField.getPassword().length == 0) {
            showErrorDialog(DecryptionDialogInformation.PASSWORD_FIELD_EMPTY);
        } else {
            try {
                decrypt(decryptFilePathField.getText(), new String(decryptPasswordField.getPassword()));
                showInformationDialog(DecryptionDialogInformation.DECRYPT_SUCCESS);
                validateDecryptedPathAndMenu();
            } catch (Exception ex) {
                showExceptionDialog(ex);
            }
        }
    }

    private void enableDecryption() {
        enableChildComponent(decryptionRadioButton.getParent(), new ArrayList<Component>() {{
            add(encryptionRadioButton);
            add(decryptionRadioButton);
        }});
        disableChildComponent(encryptionRadioButton.getParent(), new ArrayList<Component>() {{
            add(encryptionRadioButton);
            add(decryptionRadioButton);
        }});
        frame.repaint();
    }

    private void enableEncryption() {
        enableChildComponent(encryptionRadioButton.getParent(), new ArrayList<Component>() {{
            add(encryptionRadioButton);
            add(decryptionRadioButton);
        }});
        disableChildComponent(decryptionRadioButton.getParent(), new ArrayList<Component>() {{
            add(encryptionRadioButton);
            add(decryptionRadioButton);
        }});
        frame.repaint();
    }

    private static void disableChildComponent(Container parent, List<Component> exceptions) {
        for (Component component : parent.getComponents()) {
            if (component instanceof Container) {
                disableChildComponent((Container) component, exceptions);
            }
            if (exceptions == null || !exceptions.contains(component)) {
                component.disable();
                component.setEnabled(false);
            }
        }
    }

    private static void enableChildComponent(Container parent, List<Component> exceptions) {
        for (Component component : parent.getComponents()) {
            if (component instanceof Container) {
                enableChildComponent((Container) component, exceptions);
            }
            if (exceptions == null || !exceptions.contains(component)) {
                component.enable();
                component.setEnabled(true);
            }
        }
    }

    private void validateEncryptedPathAndMenu() {
        if (encryptedFilePath != null) {
            encryptedPathTextField.setText("Encrypted file path: " + encryptedFilePath);
            encryptedPathTextField.setVisible(true);
            encryptOpenFolderButton.setVisible(true);
        } else {
            encryptedPathTextField.setVisible(false);
            encryptOpenFolderButton.setVisible(false);
        }
    }

    private void validateDecryptedPathAndMenu() {
        if (decryptedFilePath != null) {
            decryptedPathTextField.setText("Decrypted file path: " + decryptedFilePath);
            decryptedPathTextField.setVisible(true);
            decryptOpenFileButton.setVisible(true);
        } else {
            decryptedPathTextField.setVisible(false);
            decryptOpenFileButton.setVisible(false);
        }
    }

    private void keyGeneration(String id, char[] password) throws Exception {
        File keysDirFile = new File(keysDir);
        if (!keysDirFile.exists()) {
            keysDirFile.mkdirs();
        }

        KeyPair rsaSignKeyPair = BCPGPKeyGenTools.generateRsaKeyPair(2048);
        KeyPair rsaEncryptKeyPair = BCPGPKeyGenTools.generateRsaKeyPair(2048);

        PGPKeyRingGenerator pgpKeyRingGen = BCPGPKeyGenTools.createPGPKeyRingGeneratorForRSAKeyPair(
                rsaSignKeyPair,
                rsaEncryptKeyPair,
                id,
                password
        );

        BCPGPKeyGenTools.exportSecretKey(pgpKeyRingGen, secKeyFile, true);
        BCPGPKeyGenTools.exportPublicKey(pgpKeyRingGen, pubKeyFile, true);
    }

    private void showExceptionDialog(Exception e) {
        showExceptionDialog(e.getMessage(), e.getMessage());
    }

    private void showExceptionDialog(String message, String title) {
        JOptionPane.showMessageDialog(panel1,
                message,
                title,
                JOptionPane.ERROR_MESSAGE);
    }

    private void showErrorDialog(IDialogInformation error) {
        JOptionPane.showMessageDialog(panel1,
                error.getMessage(),
                error.getTitle(),
                JOptionPane.ERROR_MESSAGE);
    }

    private void showInformationDialog(IDialogInformation error) {
        JOptionPane.showMessageDialog(panel1,
                error.getMessage(),
                error.getTitle(),
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void checkFileExist(File file) throws FileNotFoundException {
        if (!file.exists()) {
            throw new FileNotFoundException(file.getName() + " not found");
        }
    }

    private void encrypt(String filename, char[] privateKeyPass) throws Exception {
        File file = new File(filename);
        checkFileExist(file);

        File encryptingFolder = new File(file.getParentFile().getAbsolutePath() + File.separator + ENCRYPT_DIR);
        if (!encryptingFolder.exists()) {
            encryptingFolder.mkdir();
        }

        File encryptedFile = new File(file.getParentFile().getAbsolutePath() + File.separator + ENCRYPT_DIR + File.separator + file.getName());

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath(PUB_KEY_PATH);
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(PRIVATE_KEY_PATH);

        encryptor.setSigningPrivateKeyPassword(new String(privateKeyPass));
        encryptor.encryptFile(file, encryptedFile);
        encryptedFilePath = encryptedFile.getAbsolutePath();
    }

    private void decrypt(String filename, String passwordString) throws Exception {
        File file = new File(filename);
        checkFileExist(file);

        File decryptedFile = null;
        boolean fileExistBeforeDecrypt = false;

        try {
            BCPGPDecryptor decryptor = new BCPGPDecryptor();
            decryptor.setPrivateKeyFilePath(PRIVATE_KEY_PATH);
            decryptor.setPassword(passwordString);
            decryptor.setSigned(true);
            String originalName = file.getName();
            String decryptFileName;
            if (originalName.endsWith(ENCRYPTION_EXT))
                decryptFileName = originalName.substring(0, originalName.length() - 4);
            else
                decryptFileName = originalName;

            File decryptingFolder = new File(file.getParentFile().getAbsolutePath() + File.separator + DECRYPT_DIR);
            if (!decryptingFolder.exists()) {
                decryptingFolder.mkdir();
            }

            decryptedFile = new File(file.getParentFile().getAbsolutePath() + File.separator + DECRYPT_DIR + File.separator + decryptFileName);
            fileExistBeforeDecrypt = decryptedFile.exists();

            decryptor.setSigningPublicKeyFilePath(PUB_KEY_PATH);
            decryptor.decryptFile(file, decryptedFile);
            decryptedFilePath = decryptedFile.getAbsolutePath();

        } catch (Exception e) {
            System.out.println("Failed to decrypt file. [" + e.toString() + "]");

            // If decrypt file not exist before decrypt, then clean up
            if (!fileExistBeforeDecrypt) {
                if (decryptedFile != null && decryptedFile.exists()) {
                    decryptedFile.delete();
                }
            }

            throw e;
        }
    }

    public static void main(String[] args) {
        GUIForm guiForm = new GUIForm();
        guiForm.frame = new JFrame(APPLICATION_NAME);
        guiForm.fc.setCurrentDirectory(new File("."));
        guiForm.enableEncryption();
        ButtonGroup btnGroup = new ButtonGroup();
        btnGroup.add(guiForm.encryptionRadioButton);
        btnGroup.add(guiForm.decryptionRadioButton);
        guiForm.frame.add(guiForm.fc);
        guiForm.frame.setContentPane(guiForm.panel1);
        Dimension defaultDimension = new Dimension(700, 180);
        guiForm.frame.setMinimumSize(defaultDimension);
        guiForm.frame.setSize(defaultDimension);
        guiForm.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        guiForm.encryptedPathTextField.setBorder(BorderFactory.createEmptyBorder());
        guiForm.decryptedPathTextField.setBorder(BorderFactory.createEmptyBorder());
        guiForm.frame.pack();
        guiForm.frame.setVisible(true);
        showKeyGenMenu(guiForm);
        showEncryptMenu(guiForm);
        showDecryptMenu(guiForm);
        guiForm.validateEncryptedPathAndMenu();
        guiForm.validateDecryptedPathAndMenu();
    }

    private static void showKeyGenMenu(GUIForm guiForm) {
        if (guiForm.secKeyFile.exists() && guiForm.pubKeyFile.exists()) {
            guiForm.keyGenerateButton.getParent().hide();
            guiForm.frame.setMinimumSize(new Dimension(700, 300));
            guiForm.frame.invalidate();
        } else {
            guiForm.keyGenerateButton.getParent().show();
        }
    }

    private static void showEncryptMenu(GUIForm guiForm) {
        if (guiForm.secKeyFile.exists() && guiForm.pubKeyFile.exists()) {
            guiForm.encryptButton.getParent().setVisible(true);
        } else {
            guiForm.encryptButton.getParent().setVisible(false);
        }
    }

    private static void showDecryptMenu(GUIForm guiForm) {
        if (guiForm.secKeyFile.exists() && guiForm.pubKeyFile.exists()) {
            guiForm.decryptButton.getParent().setVisible(true);
        } else {
            guiForm.decryptButton.getParent().setVisible(false);
        }
    }

    public void setData(KeyGenerationBean data) {
        keyGenIdField.setText(data.getKeyGenerationID());
        keyGenPasswordField.setText(data.getKeyGenerationPassword());
    }

    public void getData(KeyGenerationBean data) {
        data.setKeyGenerationID(keyGenIdField.getText());
        data.setKeyGenerationPassword(keyGenPasswordField.getText());
    }

    public boolean isModified(KeyGenerationBean data) {
        if (keyGenIdField.getText() != null ? !keyGenIdField.getText().equals(data.getKeyGenerationID()) : data.getKeyGenerationID() != null)
            return true;
        if (keyGenPasswordField.getText() != null ? !keyGenPasswordField.getText().equals(data.getKeyGenerationPassword()) : data.getKeyGenerationPassword() != null)
            return true;
        return false;
    }

    public void setData(EncryptionBean data) {
        encryptFilePathField.setText(data.getSourceFilePath());
        encryptPasswordField.setText(data.getPassword());
    }

    public void getData(EncryptionBean data) {
        data.setSourceFilePath(encryptFilePathField.getText());
        data.setPassword(encryptPasswordField.getText());
    }

    public boolean isModified(EncryptionBean data) {
        if (encryptFilePathField.getText() != null ? !encryptFilePathField.getText().equals(data.getSourceFilePath()) : data.getSourceFilePath() != null)
            return true;
        if (encryptPasswordField.getText() != null ? !encryptPasswordField.getText().equals(data.getPassword()) : data.getPassword() != null)
            return true;
        return false;
    }

    public void setData(DecyptionBean data) {
        decryptPasswordField.setText(data.getPassword());
        decryptFilePathField.setText(data.getSourceFilePath());
    }

    public void getData(DecyptionBean data) {
        data.setPassword(decryptPasswordField.getText());
        data.setSourceFilePath(decryptFilePathField.getText());
    }

    public boolean isModified(DecyptionBean data) {
        if (decryptPasswordField.getText() != null ? !decryptPasswordField.getText().equals(data.getPassword()) : data.getPassword() != null)
            return true;
        if (decryptFilePathField.getText() != null ? !decryptFilePathField.getText().equals(data.getSourceFilePath()) : data.getSourceFilePath() != null)
            return true;
        return false;
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.setPreferredSize(new Dimension(-1, -1));
        panel1.setBorder(BorderFactory.createTitledBorder(""));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_NORTH, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel2.setBorder(BorderFactory.createTitledBorder("Key Generation"));
        final JLabel label1 = new JLabel();
        label1.setText("Identity");
        panel2.add(label1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(40, 16), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Password  ");
        panel2.add(label2, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(40, 16), null, 0, false));
        keyGenIdField = new JTextField();
        keyGenIdField.setToolTipText("The identity of the key owner, could be Biller ID");
        panel2.add(keyGenIdField, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        keyGenPasswordField = new JPasswordField();
        panel2.add(keyGenPasswordField, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        keyGenerateButton = new JButton();
        keyGenerateButton.setText("Generate");
        panel2.add(keyGenerateButton, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setFont(new Font(label3.getFont().getName(), Font.ITALIC, 10));
        label3.setForeground(new Color(-16777216));
        label3.setText("Please enter your Biller ID");
        panel2.add(label3, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setFont(new Font(label4.getFont().getName(), Font.ITALIC, 10));
        label4.setForeground(new Color(-16777216));
        label4.setText("Please enter the password for encryption");
        panel2.add(label4, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel3, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel3.setBorder(BorderFactory.createTitledBorder(""));
        final JLabel label5 = new JLabel();
        label5.setText("File path");
        panel3.add(label5, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(27, 16), null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Password  ");
        panel3.add(label6, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(27, 16), null, 0, false));
        encryptFilePathField = new JTextField();
        panel3.add(encryptFilePathField, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        encryptPasswordField = new JPasswordField();
        panel3.add(encryptPasswordField, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        encryptButton = new JButton();
        encryptButton.setText("Encrypt");
        panel3.add(encryptButton, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        encryptionRadioButton = new JRadioButton();
        encryptionRadioButton.setSelected(true);
        encryptionRadioButton.setText("Encryption");
        panel3.add(encryptionRadioButton, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        encryptFileChooseButton = new JButton();
        encryptFileChooseButton.setText("...");
        panel3.add(encryptFileChooseButton, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, new Dimension(100, -1), null, null, 0, false));
        encryptOpenFolderButton = new JButton();
        encryptOpenFolderButton.setText("Open folder");
        panel3.add(encryptOpenFolderButton, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, new Dimension(100, -1), null, null, 0, false));
        encryptedPathTextField = new JTextField();
        encryptedPathTextField.setAutoscrolls(true);
        encryptedPathTextField.setEditable(false);
        panel3.add(encryptedPathTextField, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel4, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel4.setBorder(BorderFactory.createTitledBorder(""));
        final JLabel label7 = new JLabel();
        label7.setText("File path");
        panel4.add(label7, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(50, 16), null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("Password  ");
        panel4.add(label8, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(50, 16), null, 0, false));
        decryptFilePathField = new JTextField();
        panel4.add(decryptFilePathField, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        decryptPasswordField = new JPasswordField();
        panel4.add(decryptPasswordField, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        decryptButton = new JButton();
        decryptButton.setText("Decrypt");
        panel4.add(decryptButton, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        decryptFileChooseButton = new JButton();
        decryptFileChooseButton.setText("...");
        panel4.add(decryptFileChooseButton, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, new Dimension(100, -1), null, null, 0, false));
        decryptionRadioButton = new JRadioButton();
        decryptionRadioButton.setText("Decryption");
        panel4.add(decryptionRadioButton, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        decryptedPathTextField = new JTextField();
        decryptedPathTextField.setEditable(false);
        panel4.add(decryptedPathTextField, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        decryptOpenFileButton = new JButton();
        decryptOpenFileButton.setText("  Open file   ");
        panel4.add(decryptOpenFileButton, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, new Dimension(100, -1), null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panel1;
    }
}
