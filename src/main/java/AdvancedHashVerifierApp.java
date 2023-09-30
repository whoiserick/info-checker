import org.apache.commons.codec.digest.DigestUtils;
import org.apache.tika.Tika;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AdvancedHashVerifierApp {
    private final JTextArea resultTextArea;

    public AdvancedHashVerifierApp() {
        // Sets the system's LookAndFeel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        JFrame frame = new JFrame("Hash Verifier");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(635, 440);
        frame.setLayout(new FlowLayout());
        frame.getContentPane().setBackground(new Color(45, 45, 60)); // Purple Background

        JButton selectFileButton = new JButton("Select the archive");
        selectFileButton.setBackground(new Color(85, 85, 100)); // Background
        selectFileButton.setForeground(Color.BLACK); // Black text

        resultTextArea = new JTextArea(15, 70);
        resultTextArea.setEditable(false);
        resultTextArea.setBackground(new Color(65, 65, 80)); // Text area background
        resultTextArea.setForeground(Color.WHITE); // White text
        resultTextArea.setCaretColor(Color.WHITE); // White cursor

        selectFileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(null);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                calculateHashes(selectedFile);
            }
        });

        frame.add(selectFileButton);
        frame.add(new JScrollPane(resultTextArea));

        frame.setVisible(true);
    }

    private void calculateHashes(File file) {
        try {
            Path path = file.toPath();

            // MD5
            String md5 = DigestUtils.md5Hex(Files.newInputStream(path));

            // SHA-1
            String sha1 = DigestUtils.sha1Hex(Files.newInputStream(path));

            // SHA-256
            String sha256 = DigestUtils.sha256Hex(Files.newInputStream(path));

            // Vhash
            String vhash = DigestUtils.sha256Hex(Files.newInputStream(path, StandardOpenOption.READ));

            // SSDEEP
            String ssdeep = calculateSsdeepHash(file);

            // File type
            Tika tika = new Tika();
            String fileType = tika.detect(file);

            // Magic number (first 4 bytes)
            byte[] magicNumberBytes = Files.readAllBytes(path);
            String magicNumber = bytesToHex(Arrays.copyOfRange(magicNumberBytes, 0, 4));

            // File size in bytes
            long fileSize = Files.size(path);

            // Show results
            resultTextArea.setText(
                    "MD5: " + md5 + "\n" +
                            "SHA-1: " + sha1 + "\n" +
                            "SHA-256: " + sha256 + "\n" +
                            "Vhash: " + vhash + "\n" +
                            "SSDEEP: " + ssdeep + "\n" +
                            "File Type: " + fileType + "\n" +
                            "Magic Number: " + magicNumber + "\n" +
                            "File size (bytes): " + fileSize
            );

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String calculateSsdeepHash(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] buffer = new byte[1024];
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            assert md != null;
            md.update(buffer, 0, bytesRead);
        }
        assert md != null;
        byte[] hash = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02x", b));
        }
        return hexStringBuilder.toString();
    }

    public static void main(String[] args) {
        new AdvancedHashVerifierApp();
    }
}
