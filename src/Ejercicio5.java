import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

public class Ejercicio5 {
    final static Xifrar xifrar = new Xifrar();


    public static void Activitat1_1() throws UnsupportedEncodingException {
        Scanner sc = new Scanner(System.in);
        KeyPair keys = xifrar.randomGenerate(1024);
        System.out.println("Introduce una palabra");
        String paraula = sc.nextLine();
        byte[] paraulaByte = paraula.getBytes();
        byte[] paraulaEncriptada = xifrar.encryptData( paraulaByte, keys.getPublic());
        String encriptedString = new String(xifrar.decryptData(paraulaEncriptada, keys.getPrivate()), "UTF-8");
        System.out.println("Palabra cifrada---> " +new String(paraulaEncriptada));
        System.out.println();
        System.out.println("Palabra Desencriptada---> "+encriptedString);

    }


    public static void Activitat1_2() throws Exception {
        Scanner sc = new Scanner(System.in);
        String keystorePath = "C:\\Users\\DANILLERA\\Desktop\\my-release-key.keystore";
        System.out.println("Introduce la contrasenya del keystore");
        //La contraseña es "usuario"
        String keystoreKey = sc.nextLine();
        KeyStore myKeystore = xifrar.loadKeyStore(keystorePath, keystoreKey);
        System.out.println();
        System.out.println("Activitat 1.i.2.1");
        System.out.println(myKeystore.getType());
        System.out.println();
        System.out.println("Activitat 1.i.2.2");
        System.out.println(myKeystore.size());
        System.out.println("Hay"+ myKeystore.size() +" clave");
        System.out.println();
        System.out.println("Activitat 1.i.2.3");
        Enumeration<String> enumeration = myKeystore.aliases();
        while(enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            System.out.println("Alias: " + alias);
            if(enumeration.equals(myKeystore.size()))
                break;
        }
        System.out.println();
        System.out.println();
        System.out.println("Activitat 1.i.2.4 ");
        System.out.println(myKeystore.getCertificate("dani"));
        System.out.println();
        System.out.println("Activitat 1.i.2.5");
        System.out.println(myKeystore.getCertificate("dani").getPublicKey().getAlgorithm());
        //La parte final no me funcionaba

    }
    public static void Activitat1_3() throws FileNotFoundException, CertificateException {
        System.out.println(xifrar.getPublicKey("C:\\Users\\DANILLERA\\Desktop\\jordi.cer"));
    }

    public static void Activitat1_4() throws Exception {
        KeyStore ks = xifrar.loadKeyStore("C:\\Users\\DANILLERA\\Desktop\\my-release-key.keystore", "usuario");
        System.out.println(xifrar.getPublicKey(ks,"dani", "usuario" ));

    }

    public static void Activitat1_5(){

        System.out.println("Clave privada");
        KeyPair newKey = xifrar.randomGenerate(1024);
        PrivateKey privateKey = newKey.getPrivate();
        byte[] textComprobarSignatura ="usuario".getBytes();
        System.out.println( new String(xifrar.signData(textComprobarSignatura, privateKey)));

    }

    public static void Activitat1_6()  {

        System.out.println("Comprovando la validez");
        System.out.println("..................................");
        KeyPair newKey = xifrar.randomGenerate(1024);
        KeyPair newKey2 = xifrar.randomGenerate(1024);
        PublicKey publicKey2 = newKey2.getPublic();
        PrivateKey privateKey = newKey.getPrivate();
        PublicKey publicKey = newKey.getPublic();
        byte[] ComprobarSignatura ="mi firma".getBytes();
        byte[] signatura = xifrar.signData(ComprobarSignatura,privateKey);
        boolean comprobar = xifrar.validateSignature(ComprobarSignatura, signatura, publicKey);
        if(comprobar){
            System.out.println("Validez correcta");
        }
        else{
            System.out.println("Validez Incorecta");
        }

    }

    public static void Activitat2(){
        KeyPair newKey = xifrar.randomGenerate(1024);
        System.out.println();
        String frase = "Hola buenos dias";
        byte[][] textEncriptat = xifrar.encryptWrappedData(frase.getBytes(), newKey.getPublic());
        byte[] textDesencriptat = xifrar.decryptWrappedData(textEncriptat, newKey.getPrivate());
        System.out.println("Mensaje encriptado -----> "+textEncriptat); //Tambien se puede usar el formato toSring
        System.out.println("Mensaje desencriptado -----> " +new String(textDesencriptat, StandardCharsets.UTF_8));
    }



    public static void main(String[] args) throws Exception {
        //Aqui estan todos los ejercicios hay que ir descomentando para que se ejecutan :)

        Activitat1_1();
        // Activitat1_2();
        //Activitat1_3();
        //Activitat1_4();
        //Activitat1_5();
        //Activitat1_6();
        //Activitat2();
    }
}
