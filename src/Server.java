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
            System.out.println("Ожидание клиента ...");

            Socket socket = ss.accept();
            System.out.println("Клиент подключен!!!");
            System.out.println();

            // Берем входной и выходной потоки сокета, теперь можем получать и отсылать данные клиенту.
            InputStream sin = socket.getInputStream();
            OutputStream sout = socket.getOutputStream();

            // Конвертируем потоки в другой тип, чтоб легче обрабатывать текстовые сообщения.
            DataInputStream in = new DataInputStream(sin);
            DataOutputStream out = new DataOutputStream(sout);

            String login = null;
            String password = null;
            String publicKey = null;
            while(true) {
                /////////////////////////Регистрация/////////////////////////

                out.writeUTF("      Регистрация.\nВведите ваш логин: ");
                login = in.readUTF(); // клиент передает логин для регистрации
                out.writeUTF("\nВведите ваш пароль: ");
                password = in.readUTF(); // клиент передает пароль к своему логину для регистрации
                System.out.println("\nПользователь: логин - " + login + ", пароль - " + password + " зарегистрирован!");
                registration(login, password); // сохранение в базу данных сервера
                /*System.out.println("\nЗарегистрированные пользователи: ");
                for (Base i : users){
                    System.out.println("Логин - " + i.getLogin() + ", соль - " + i.getSalt() + ", верификатор - " + i.getPassVerifier());
                }*/

                /////////////////////////Авторизация/////////////////////////

                boolean errlogin = false;
                out.writeUTF("      Авторизация.\nВведите ваш логин: ");
                login = in.readUTF(); // клиент передает свой логин с целью авторизации
                for (Base i : users){
                    if (login.equals(i.getLogin())){
                        errlogin = true;
                        publicKey = in.readUTF(); // клиент передает А - публичный ключ
                        A = A.add(new BigInteger(publicKey)); // из строки в бигинтеджер

                        BigInteger s = i.getSalt();
                        out.writeUTF(s.toString()); // соль передается клиенту
                        Thread.sleep(3000);
                        out.writeUTF(authorizationLoginUser(login, A)); // передается клиенту B

                        out.writeUTF("\nВведите ваш пароль: ");
                        BigInteger v = i.getPassVerifier();
                        String x = authorizationServer(v, A);
                        String y = in.readUTF();
                        String z = in.readUTF();

                        if (Kbool(x, y, z)){
                            out.writeUTF("\nАвторизация прошла успешно!!!");
                        }
                        else {
                            out.writeUTF("\nОшибка!");
                        }

                    }
                }
                if(!errlogin){
                    System.err.println("\nОшибка! Такого логина не существует!");
                    break;
                }
                out.flush(); // заставляем поток закончить передачу данных.
                break;
            }
        } catch(Exception x) { x.printStackTrace(); }
    }

    public final static BigInteger modulus_N =
            new BigInteger("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16); // модуль для арифм. операций srp

    // g  - генератор по модулю N => для любого 0 < X < N существует и единственный x такой, что g^x % N = X.
    public final static BigInteger generator_g =
                    new BigInteger("2", 10);

    // k - параметр-множитель.
    public final static BigInteger multiplier_k =
                new BigInteger("3", 10);


    // u - произвольный параметр для кодирования.
    public final static BigInteger scrambler =
            new BigInteger(128, new Random());

    // H - используемая хеш-функция. Используется SHA-1.
    public final static HashFunction function_Hash = new HashFunction();

    // клиенты, зрегистрированные на сервере.
    private static List<Base> users = new ArrayList<Base>();

    public static void registration(String inputLogin, String inputPass) { // подготовка к хранению данных пользователя
        String login = inputLogin;
        String password = inputPass;

        // Вычисляем необходимые при регистрации параметры на стороне клиента //
        BigInteger salt = getSalt(); // соль генерируется на клиенте

        // H(s, p) - взятие хеша от соли и логина с паролем
        BigInteger x = new BigInteger( Server.function_Hash.getHash(
                salt.toByteArray(),
                Server.function_Hash.getHash(new String(login + ":" + password).getBytes())
        ));

        // v = g ^ x - верификатор
        BigInteger verifier = Server.generator_g.modPow(x, Server.modulus_N); //Server.generator_g.modPow(x, Server.modulus_N);


        // отправляем данные на сервер
        // отправляется тройка:
        // I - логин пользователя
        // s - сгенерированная соль
        // v - верификатор пользователя
        Server.registrationUser(login, salt, verifier);
    }

    public static String authorizationLoginUser(String login, BigInteger A) {

        BigInteger v = null;

        
        for (Base i : users){
            if (login.equals(i.getLogin())){
                v = i.getPassVerifier();

            }
        }

        // Генерируем приватный ключ b (случайное число) и публичный ключ B //
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

        // Вычисляем сессионный ключ //
        // A * (v^u % N)
        BigInteger firstPart = A.multiply(v.modPow(scrambler, modulus_N));

        // S = ((A*(v^u % N)) ^ b) % N
        BigInteger S = firstPart.modPow(privateKey, modulus_N);


        // K = H(S)
        BigInteger K = new BigInteger(function_Hash.getHash(S.toByteArray()));

        return K.toString();
    }

    public static void registrationUser(String login, BigInteger s, BigInteger v) { // заполнение базы пользователей

        // После этого сервер хранит пару (I, s, v) в своей базе данных
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
        private String login_s; // логин
        private BigInteger salt_s; // сгенерированная соль при регистрации
        private BigInteger verifier_v; // верификатор пароля

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
