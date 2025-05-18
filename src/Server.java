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

    }
}
