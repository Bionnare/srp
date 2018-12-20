import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.util.*;

public class Client {
    private static String login = null;
    private static String password = null;
    private static String test = null;
    private static BigInteger B = BigInteger.valueOf(0);
    private static BigInteger s = BigInteger.valueOf(0);
    private static BigInteger privateKey;
    private static BigInteger publicKey;

    public static void main(String[] ar) {
        int serverPort = 3128;
        String address = "127.0.0.1";

        try {
            InetAddress ipAddress = InetAddress.getByName(address); // ������� ������ ������� ���������� ������������� IP-�����.
            Socket socket = new Socket(ipAddress, serverPort); // ������� ����� ��������� IP-����� � ���� �������.
            System.out.println("����������� � ������� ������ �������!\n");

            // ����� ������� � �������� ������ ������, ������ ����� �������� � �������� ������ ��������.
            InputStream sin = socket.getInputStream();
            OutputStream sout = socket.getOutputStream();

            // ������������ ������ � ������ ���, ���� ����� ������������ ��������� ���������.
            DataInputStream in = new DataInputStream(sin);
            DataOutputStream out = new DataOutputStream(sout);

            // ������� ����� ��� ������ � ����������.
            BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
            String line = null;

            while (true) {
                /////////////////////////�����������/////////////////////////

                line = in.readUTF();
                System.out.println(line);
                login = keyboard.readLine();
                out.writeUTF(login); // �������� ����� ��� �����������
                line = in.readUTF();
                System.out.println(line);
                test = keyboard.readLine();
                out.writeUTF(test); // �������� ������ ��� �����������

                /////////////////////////�����������/////////////////////////

                line = in.readUTF();
                System.out.println(line);
                login = keyboard.readLine();
                out.writeUTF(login); // ����� ��� �����������
                Thread.sleep(3000);
                out.writeUTF(authorizationLogin(login)); // �������� A

                line = in.readUTF(); // �������� ����
                s = s.add(new BigInteger(line)); // �� ������ � �����������
                line = in.readUTF(); // �������� B
                B = B.add(new BigInteger(line)); // �� ������ � �����������

                line = in.readUTF();
                System.out.println(line);
                password = keyboard.readLine();
                Kerr(password, test);

                String x = authorizationPassword(password, s, B);
                System.out.println("K = " + x);
                out.writeUTF(x);

                out.writeUTF(Kerr(password, test));

                out.flush(); // ���������� ����� ��������� �������� ������.
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }


    // ��������� ����������� ������������ (��������� ������ �����).
    public static String authorizationLogin(String inputLogin) {
        login = inputLogin;

        // ���������� ��������� ���� a (��������� �����) � ��������� ���� � //
        privateKey = new BigInteger(128 , new Random());

        // A = (g ^ a) % N
        publicKey = Server.generator_g.modPow(privateKey, Server.modulus_N);

        // ������������ ���� ����: ����� � �������� ���� ������������
        return publicKey.toString();
    }

    // ��������� ����������� ������������ (��������� ��������� ����).
    public static String authorizationPassword(String password, BigInteger salt, BigInteger B) {


        // ��������� ���������� ���� //
        BigInteger scrambler = Server.scrambler;

        // H(s, p) - ������ ���� �� ���� � ������ � �������
        BigInteger x = new BigInteger( Server.function_Hash.getHash(
                salt.toByteArray(),
                Server.function_Hash.getHash(new String(login + ":" + password).getBytes())
        ));

        // a + u * x
        BigInteger aux = privateKey.add(scrambler.multiply(x));

        // (B - ( (g^x % N) *k)) ^ (a + u*x) (% N)
        BigInteger S = B.subtract((Server.generator_g.modPow(x, Server.modulus_N)).
                multiply(Server.multiplier_k)).modPow(aux, Server.modulus_N);

        // K = H(S)
        BigInteger K = new BigInteger(Server.function_Hash.getHash(S.toByteArray()));

        return K.toString();
    }

    public static String Kerr(String x, String y) {
        String bool = "false";

        if (x.equals(y)){
            bool = "true";
        }
        return bool;
    }

}