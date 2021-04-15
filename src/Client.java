import java.io.*;
import java.net.*;
import java.util.Scanner;

/**
 * La classe client se connecte à un serveur à l'aide d'une socket.
 * Une fois qu'elle a établie la connexion, elle propose à l'utilisateur des saisie clavier afin d'envoyer des messages
 * l'envoi et la réception de message se fait à tour de rôle
 */
public class Client {

    public static void main(String[] args) throws Exception {

        /** CONFIGURATION SOCKET, INPUT ET OUPUT */

            /** Instanciation d'une socket d'écoute sur 1234 */
            Socket sock = new Socket("127.0.0.1",1234);

            /** input et output banché sur la socket */
            DataInputStream in = new DataInputStream(sock.getInputStream());
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());

            /** Instanciation gestionnaire d'encryptage / décryptage */
            GestionnaireCryptage E = new GestionnaireCryptage("emetteur", "RSA");

        /** ------ ECHANGE DES CLEFS ------ */

            /** récupère une clé publique */
            System.out.println("Récupération de la clef publique");
            int size = in.read();
            E.setPublicKey(in.readNBytes(size));

            /** code la clé secrète avec la clé publique */
            System.out.println("Encodage de la clef secrète");
            E.encodeSecretKey();

            /** transmet la clé codée au récepteur */
            System.out.println("Envoi de la clef secrète");
            out.write(E.sendSecretKey().length);
            out.write(E.sendSecretKey());

        /** ------ LES PREMIERS ECHANGES ------ */

            /** Attend la saisie du message au clavier */
            System.out.println("Veuillez saisir votre message : ");
            Scanner sc = new Scanner(System.in);
            E.setMessage(sc.nextLine());

            /** Code le message avec DES */
            E.encodeMessage();

            /** Transmet le message au récepteur */
            out.write(E.getMessage().length);
            out.write(E.getMessage());

            /** Attend la réponse du récepteur */
            System.out.println("Attend la réponse du serveur");
            size = in.read();
            /** Réception, décodage message avec DES, et affichage */
            E.receiveMessage(in.readNBytes(size)).decodeMessage().readMessage();

        /** ------ BOUCLE D'ECHANGE ------ */

            while( true ) {

                System.out.println("Veuillez saisir votre message");
                String str = sc.nextLine();
                E.setMessage(str).encodeMessage();
                out.write(E.getMessage().length);
                out.write(E.getMessage());

                if(str.equals("stop")) {
                    break;
                }

                System.out.println("En attente d'un message");
                size = in.read();
                System.out.println("Le Serveur dit : ");
                E.receiveMessage(in.readNBytes(size)).decodeMessage().readMessage();

                if(str.equals("stop")) {
                    break;
                }

            }

            /** Fermeture des flux de lecture, écriture, et de la socket d'échanges */
            in.close();
            out.close();
            sock.close();

    }
}


