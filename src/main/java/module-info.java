module org.undefined.uvault {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.swing;
    requires java.desktop;
    
    //requires org.graalvm.sdk;
    // requires org.graalvm.truffle;

    opens org.undefined.uvault.pages to javafx.fxml;
    opens org.undefined.uvault to javafx.fxml;

    exports org.undefined.uvault;
}