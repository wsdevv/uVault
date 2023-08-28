package org.undefined.uvault.pages;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Label;
import org.undefined.uvault.UVaultMain;

import java.io.IOException;

//import org.graalvm.polyglot.*;
//import java.io.*;

public class AuthenticationController {


    @FXML
    protected void navToCreateNewVault() throws IOException {
        System.out.println("[DEBUG]: Creating New Vault...");
        FXMLLoader fxmlLoader = new FXMLLoader(UVaultMain.class.getResource("create_new_vault.fxml"));
        UVaultMain.scene.setRoot(fxmlLoader.load());

    }
}