package org.undefined.uvault.pages;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox; 
import org.undefined.uvault.UVaultMain;
import javafx.scene.layout.FlowPane;


import java.io.IOException;



public class VaultListController {

    @FXML 
    protected FlowPane vaultListContainer;

 
    @FXML
    protected void newv() {
            try {
            FXMLLoader newVault = new FXMLLoader(UVaultMain.class.getResource("vault_list_item.fxml")); 
            
            vaultListContainer.getChildren().add(newVault.load());
            }
            catch (Exception e) {
                System.out.println(e);
            }
    }

}