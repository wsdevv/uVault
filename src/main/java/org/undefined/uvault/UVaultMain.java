package org.undefined.uvault;

import java.util.HashMap; 
import java.util.ArrayList;
import java.util.LinkedHashMap;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.layout.AnchorPane;
import java.io.IOException;


public class UVaultMain extends Application {
    public static native int generateNewVault(String name, char[] password, long passwordLength);
    public static native long openVault();
    public static native boolean vaultPathExists();
    public static native String[] fetchVaults();
    public static native int closeVault(long vca);

    public static native int                                       vaultCommand(long vca, String cmmd);

    // can only open one vault at a time
    // TODO: allow opening multiple vaults at a time
    public static long vaultCommunicationAddress;

    // containsVaultName
    public static LinkedHashMap<String, Boolean> vaultList;
    public static Scene scene = new Scene(new AnchorPane(), 320, 240);

    @Override
    public void start(Stage stage) throws IOException {
        System.load("/home/wesley/IdeaProjects/UVault/src/backend/target/debug/libbackend.so");
        
        FXMLLoader fxmlLoader = new FXMLLoader(UVaultMain.class.getResource("vault_list.fxml"));
        if (UVaultMain.vaultPathExists()) { 
            System.out.println("[DEBUG]: Vault path exists");
            UVaultMain.scene.setRoot(fxmlLoader.load());
         
        }
        else {
            fxmlLoader = new FXMLLoader(UVaultMain.class.getResource("authenticate.fxml"));
            scene.setRoot(fxmlLoader.load());
        }
        stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();

    }

    public static void main(String[] args) {
        launch();
        if (vaultCommunicationAddress!=0) closeVault(vaultCommunicationAddress);
    }
}