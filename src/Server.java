import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Server {
    private static BigInteger A = BigInteger.valueOf(0);
    private static BigInteger privateKey;
    private static BigInteger publicKey;
    private static BigInteger salt;

    public static void main(String[] ar) {
        int port = 3128;
        try {
            ServerSocket ss = new ServerSocket(port);
            System.out.println("�������� ������� ...");

            Socket socket = ss.accept();
            System.out.println("������ ���������!!!");
            System.out.println();

            // ����� ������� � �������� ������ ������, ������ ����� �������� � �������� ������ �������.
            InputStream sin = socket.getInputStream();
            OutputStream sout = socket.getOutputStream();

            // ������������ ������ � ������ ���, ���� ����� ������������ ��������� ���������.
            DataInputStream in = new DataInputStream(sin);
            DataOutputStream out = new DataOutputStream(sout);

            String login = null;
            String password = null;
            String publicKey = null;
            while(true) {
                /////////////////////////�����������/////////////////////////

                out.writeUTF("      �����������.\n������� ��� �����: ");
                login = in.readUTF(); // ������ �������� ����� ��� �����������
                out.writeUTF("\n������� ��� ������: ");
                password = in.readUTF(); // ������ �������� ������ � ������ ������ ��� �����������
                System.out.println("\n������������: ����� - " + login + ", ������ - " + password + " ���������������!");
                registration(login, password); // ���������� � ���� ������ �������
                /*System.out.println("\n������������������ ������������: ");
                for (Base i : users){
                    System.out.println("����� - " + i.getLogin() + ", ���� - " + i.getSalt() + ", ����������� - " + i.getPassVerifier());
                }*/

                /////////////////////////�����������/////////////////////////

                boolean errlogin = false;
                out.writeUTF("      �����������.\n������� ��� �����: ");
                login = in.readUTF(); // ������ �������� ���� ����� � ����� �����������
                for (Base i : users){
                    if (login.equals(i.getLogin())){
                        errlogin = true;
                        publicKey = in.readUTF(); // ������ �������� � - ��������� ����
                        A = A.add(new BigInteger(publicKey)); // �� ������ � �����������

                        BigInteger s = i.getSalt();
                        out.writeUTF(s.toString()); // ���� ���������� �������
                        Thread.sleep(3000);
                        out.writeUTF(authorizationLoginUser(login, A)); // ���������� ������� B

                        out.writeUTF("\n������� ��� ������: ");
                        BigInteger v = i.getPassVerifier();
                        String x = authorizationServer(v, A);
                        String y = in.readUTF();
                        String z = in.readUTF();

                        if (Kbool(x, y, z)){
                            out.writeUTF("\n����������� ������ �������!!!");
                        }
                        else {
                            out.writeUTF("\n������!");
                        }

                    }
                }
                if(!errlogin){
                    System.err.println("\n������! ������ ������ �� ����������!");
                    break;
                }
                out.flush(); // ���������� ����� ��������� �������� ������.
                break;
            }
        } catch(Exception x) { x.printStackTrace(); }
    }

    public final static BigInteger modulus_N =
            new BigInteger("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16); // ������ ��� �����. �������� srp

    // g  - ��������� �� ������ N => ��� ������ 0 < X < N ���������� � ������������ x �����, ��� g^x % N = X.
    public final static BigInteger generator_g =
                    new BigInteger("2", 10);

    // k - ��������-���������.
    public final static BigInteger multiplier_k =
                new BigInteger("3", 10);


    // u - ������������ �������� ��� �����������.
    public final static BigInteger scrambler =
            new BigInteger(128, new Random());

    // H - ������������ ���-�������. ������������ SHA-1.
    public final static HashFunction function_Hash = new HashFunction();

    // �������, ����������������� �� �������.
    private static List<Base> users = new ArrayList<Base>();

    public static void registration(String inputLogin, String inputPass) { // ���������� � �������� ������ ������������
        String login = inputLogin;
        String password = inputPass;

        // ��������� ����������� ��� ����������� ��������� �� ������� ������� //
        BigInteger salt = getSalt(); // ���� ������������ �� �������

        // H(s, p) - ������ ���� �� ���� � ������ � �������
        BigInteger x = new BigInteger( Server.function_Hash.getHash(
                salt.toByteArray(),
                Server.function_Hash.getHash(new String(login + ":" + password).getBytes())
        ));

        // v = g ^ x - �����������
        BigInteger verifier = Server.generator_g.modPow(x, Server.modulus_N); //Server.generator_g.modPow(x, Server.modulus_N);


        // ���������� ������ �� ������
        // ������������ ������:
        // I - ����� ������������
        // s - ��������������� ����
        // v - ����������� ������������
        Server.registrationUser(login, salt, verifier);
    }

    public static String authorizationLoginUser(String login, BigInteger A) {

        BigInteger v = null;

        
        for (Base i : users){
            if (login.equals(i.getLogin())){
                v = i.getPassVerifier();

            }
        }

        // ���������� ��������� ���� b (��������� �����) � ��������� ���� B //
        privateKey = new BigInteger(128 , new Random());

        // k * v
        BigInteger firstPart = multiplier_k.multiply(v);

        // g ^ b % N
        BigInteger secondPart = generator_g.modPow(privateKey, modulus_N);

        // B = k * v + g ^ b % N
        publicKey = firstPart.add(secondPart).mod(modulus_N);

        return publicKey.toString();
    }

    public static String authorizationServer(BigInteger v, BigInteger A) {

        // ��������� ���������� ���� //
        // A * (v^u % N)
        BigInteger firstPart = A.multiply(v.modPow(scrambler, modulus_N));

        // S = ((A*(v^u % N)) ^ b) % N
        BigInteger S = firstPart.modPow(privateKey, modulus_N);


        // K = H(S)
        BigInteger K = new BigInteger(function_Hash.getHash(S.toByteArray()));

        return K.toString();
    }

    public static void registrationUser(String login, BigInteger s, BigInteger v) { // ���������� ���� �������������

        // ����� ����� ������ ������ ���� (I, s, v) � ����� ���� ������
        users.add(new Base(login, s, v));
    }

    public static boolean Kbool(String x, String y, String z) {
        boolean bool = false;

        if(z.equals("true")) {
            System.out.println("K = " + y);
            if (y.equals(y)) {
                bool = true;
            }
        }
        else {
            System.out.println("K = " + x);
        }
        return bool;
    }

    private static BigInteger getSalt() {
        int saltBits = 128;
        return new BigInteger(saltBits, new Random());
    }

    public static class Base {
        private String login_s; // �����
        private BigInteger salt_s; // ��������������� ���� ��� �����������
        private BigInteger verifier_v; // ����������� ������

        public Base(String login, BigInteger salt, BigInteger verifier) {
            this.login_s = login;
            this.salt_s = salt;
            this.verifier_v = verifier;
        }

        public String getLogin() {
            return login_s;
        }

        public BigInteger getSalt() {
            return salt_s;
        }

        public BigInteger getPassVerifier() {
            return verifier_v;
        }
    }

}
