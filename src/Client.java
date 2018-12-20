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
            InetAddress ipAddress = InetAddress.getByName(address); // создаем объект который отображает вышеописанный IP-адрес.
            Socket socket = new Socket(ipAddress, serverPort); // создаем сокет используя IP-адрес и порт сервера.
            System.out.println("Подключение к серверу прошло успешно!\n");

            // Берем входной и выходной потоки сокета, теперь можем получать и отсылать данные клиентом.
            InputStream sin = socket.getInputStream();
            OutputStream sout = socket.getOutputStream();

            // Конвертируем потоки в другой тип, чтоб легче обрабатывать текстовые сообщения.
            DataInputStream in = new DataInputStream(sin);
            DataOutputStream out = new DataOutputStream(sout);

            // Создаем поток для чтения с клавиатуры.
            BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
            String line = null;

            while (true) {
                /////////////////////////Регистрация/////////////////////////

                line = in.readUTF();
                System.out.println(line);
                login = keyboard.readLine();
                out.writeUTF(login); // отсылаем логин для регистрации
                line = in.readUTF();
                System.out.println(line);
                test = keyboard.readLine();
                out.writeUTF(test); // отсылаем пароль для регистрации

                /////////////////////////Авторизация/////////////////////////

                line = in.readUTF();
                System.out.println(line);
                login = keyboard.readLine();
                out.writeUTF(login); // логин для авторизации
                Thread.sleep(3000);
                out.writeUTF(authorizationLogin(login)); // отсылаем A

                line = in.readUTF(); // получаем соль
                s = s.add(new BigInteger(line)); // из строки в бигинтеджер
                line = in.readUTF(); // получаем B
                B = B.add(new BigInteger(line)); // из строки в бигинтеджер

                line = in.readUTF();
                System.out.println(line);
                password = keyboard.readLine();
                Kerr(password, test);

                String x = authorizationPassword(password, s, B);
                System.out.println("K = " + x);
                out.writeUTF(x);

                out.writeUTF(Kerr(password, test));

                out.flush(); // заставляем поток закончить передачу данных.
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }


    // Первичная авторизация пользователя (необходим только логин).
    public static String authorizationLogin(String inputLogin) {
        login = inputLogin;

        // Генерируем приватный ключ a (случайное число) и публичный ключ А //
        privateKey = new BigInteger(128 , new Random());

        // A = (g ^ a) % N
        publicKey = Server.generator_g.modPow(privateKey, Server.modulus_N);

        // возвращается пара вида: логин и открытый ключ пользователя
        return publicKey.toString();
    }

    // Вторичная авторизация пользователя (необходим первичный этап).
    public static String authorizationPassword(String password, BigInteger salt, BigInteger B) {


        // Вычисляем сессионный ключ //
        BigInteger scrambler = Server.scrambler;

        // H(s, p) - взятие хеша от соли и логина с паролем
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