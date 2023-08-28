package org.undefined.uvault.pages;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.TextField;
import javax.swing.JPasswordField;
import javafx.embed.swing.SwingNode;
//import javafx.scene.control.PasswordField;
import org.undefined.uvault.UVaultMain;
import javafx.scene.layout.AnchorPane;
import javafx.scene.Cursor;
import java.awt.Dimension;
import java.util.Arrays;

import java.io.IOException;

//import org.graalvm.polyglot.*;
//import java.io.*;

public class NewVaultController {
    @FXML
    protected AnchorPane root;

    @FXML
    protected TextField VaultName;

    @FXML
    protected SwingNode VaultPasswordContainer;


    private JPasswordField passwordField;

    @FXML 
    protected void initialize() {
        passwordField = new JPasswordField(); 
        passwordField.setMinimumSize(new Dimension(319,45));
        VaultPasswordContainer.setContent(passwordField);
    }

    @FXML
    protected void focusPassword() { 
        VaultPasswordContainer.requestFocus();
    }

    @FXML
    protected void createNewVault() throws IOException {
        root.setCursor(Cursor.WAIT);
        System.out.println("[FRONTEND]: Creating New Vault...");
        
        char[] password = passwordField.getPassword();
        UVaultMain.generateNewVault(VaultName.getText(), password, password.length);

        // "Zeroize" password java-side (a little harder to do, that's why we send a gc request after this)
        VaultName.setText("\0");
        passwordField.setText("\0");
        Arrays.fill(password, '\0');
 
      
        // suggest the gc to clean up any password strings (may not work)
        System.gc();
        System.out.println("[FRONTEND]: Finished Creating Vault!");
        root.setCursor(Cursor.DEFAULT);
        FXMLLoader fxmlLoader = new FXMLLoader(UVaultMain.class.getResource("save_sync_key.fxml"));
        UVaultMain.scene.setRoot(fxmlLoader.load());

    }
}