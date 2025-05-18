import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;

public class Client {
    private static SecretKey aesKey;

    public static void main(String[] args) throws Exception {
        // === Thread to receive signed messages from server ===
        Thread listener = new Thread(() -> {
            try {
                while (true) {
                    String msg = (String) in.readObject();
                    byte[] sig = (byte[]) in.readObject();

                    if (!verifySignature(msg.getBytes(), sig, serverRSAKey)) {
                        System.out.println("Signature invalid! Message tampered.");
                        continue;
                    }

                    if (msg.equalsIgnoreCase("exit")) {
                        System.out.println("Server has ended the session.");
                        socket.close();
                        System.exit(0);
                    }

                    System.out.print("\n[Server]: " + msg + "\nYou: ");
                }
            } catch (Exception e) {
                System.out.println("Server disconnected.");
                System.exit(0);
            }
        });
        listener.start();

        // === Main thread: send messages ===
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("You: ");
            String userMsg = scanner.nextLine();
            byte[] encrypted = encryptMessage(userMsg);
            out.writeObject(encrypted);

            if (userMsg.equalsIgnoreCase("exit")) {
                System.out.println("You have ended the session.");
                socket.close();
                System.exit(0);
            }
        }
    }

    private static boolean verifySignature(byte[] data, byte[] sigBytes, PublicKey pubKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(sigBytes);
    }

    private static byte[] encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(message.getBytes());
    }
}
