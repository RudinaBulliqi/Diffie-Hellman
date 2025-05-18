import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;

public class Server {
    private static SecretKey aesKey;
    private static ObjectOutputStream out;
    private static ObjectInputStream in;
    private static Socket socket;
    private static KeyPair rsaKeyPair;

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("Listening for connections...");
        socket = serverSocket.accept();
        System.out.println("Client connected.");

        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        // === Diffie-Hellman Key Exchange ===
        System.out.println("Performing Diffie-Hellman key exchange...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        KeyPair dhKeyPair = kpg.generateKeyPair();
        PrivateKey privateKey = dhKeyPair.getPrivate();
        PublicKey publicKey = dhKeyPair.getPublic();

        out.writeObject(publicKey);
        PublicKey clientPubKey = (PublicKey) in.readObject();

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privateKey);
        ka.doPhase(clientPubKey, true);
        byte[] sharedSecret = ka.generateSecret();

        aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        System.out.println("Shared secret established.");

        // === RSA Key Generation and Signature ===
        rsaKeyPair = generateRSAKeyPair();
        String welcomeMessage = "Welcome to the secure server!";
        byte[] signature = signMessage(welcomeMessage.getBytes(), rsaKeyPair.getPrivate());

        out.writeObject(rsaKeyPair.getPublic());
        out.writeObject(welcomeMessage);
        out.writeObject(signature);

        // === Thread to receive messages from client ===
        Thread receiver = new Thread(() -> {
            try {
                while (true) {
                    byte[] encrypted = (byte[]) in.readObject();
                    String decrypted = decryptMessage(encrypted);
                    if (decrypted.equalsIgnoreCase("exit")) {
                        System.out.println("Client has ended the session.");
                        socket.close();
                        System.exit(0);
                    }
                    System.out.print("\n[Client]: " + decrypted + "\nYou: ");
                }
            } catch (Exception e) {
                System.out.println("Client disconnected.");
                System.exit(0);
            }
        });
        receiver.start();

// === Main thread: send signed messages ===
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("You: ");
            String message = scanner.nextLine();
            byte[] sig = signMessage(message.getBytes(), rsaKeyPair.getPrivate());
            out.writeObject(message);
            out.writeObject(sig);

            if (message.equalsIgnoreCase("exit")) {
                System.out.println("You have ended the session.");
                socket.close();
                System.exit(0);
            }
        }

    }
    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private static byte[] signMessage(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    private static String decryptMessage(byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return new String(cipher.doFinal(encrypted));
    }
}
