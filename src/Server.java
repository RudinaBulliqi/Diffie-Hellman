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

    }
}
