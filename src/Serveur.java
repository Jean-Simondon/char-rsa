import java.io.*;
import java.net.*;
import java.lang.*;
import java.util.Scanner;
import java.net.Socket;

/**
 * La classe serveur met en place une socket d'écoute en attente de requête de la part de client
 * quand une requête lui parvient, elle lance une nouvelle socket d'échanges avec le client
 * la nouvelle socket d'échanges boucle sur des échanges de texte avec le client de manière à pouvoir lire et écrire à tour de rôle
 * Afin de gérer un échange de message codé avec protocole RSA, elle utilise la classe GestionnaireCryptage qui contient tout le code de cryptage.
 */
public class Serveur {

    public static void main(String[] args) throws Exception {

        System.out.println("Création Serveur");
        /** Préparation d'une socket serveur */
        ServerSocket sockserv = new ServerSocket(1234);
        /** Gestionnaire de cryptage / décryptage */
        GestionnaireCryptage R = new GestionnaireCryptage("recepteur", "RSA");
        /** Utile à la lecture de la taille d'un message à venir */
        int size;

        try {
            while (true)
            {
                try {

                    /** ------ CONFIGURATION SOCKET, INPUT ET OUPUT ------ */

                        /** on attend et accepte les demandes de la part de client sur une nouvelle socket */
                        Socket sockcli = sockserv.accept();

                        /** gestion des input et ouput */
                        DataInputStream in = new DataInputStream(sockcli.getInputStream()); // on branche l'écoute de cette socket sur in
                        DataOutputStream out = new DataOutputStream(sockcli.getOutputStream()); // on branche l'écriture de cette socket sur out

                    /** ------ ECHANGE DES CLEFS ------ */

                        /** Le récepteur transmet la clef publique à l'émetteur */
                        System.out.println("Envoi de la clef publique par le Serveur");
                        out.write(R.getPublicKey().getEncoded().length); // on envoi sa longueur en byte
                        out.write(R.getPublicKey().getEncoded()); // et on l'envoi ensuite pour de bon

                        /** le récepteur récupère la clef secrète codée de l'émetteur et la décode avec la clef publique */
                        System.out.println("Réception de la clef secrète par le Serveur");
                        size = in.read(); // on récupère sa longueur
                        R.setSecretKey(in.readNBytes(size)); // et on lis sa longueur en byte
                        R.decodeSecretKey(); // puis on la décode

                    /** ------ LES PREMIERS ECHANGE ------ */

                        /** le récepteur reçoit le message de l'émetteur, le décode, et le lis */
                        System.out.println("En attente du message du client");
                        size = in.read();
                        R.receiveMessage(in.readNBytes(size)).decodeMessage().readMessage();

                    /** ------ BOUCLE D'ECHANGE ------ */

                        /** Utilitaire de récupération d'entre clavier */
                        Scanner sc = new Scanner(System.in);

                        while( true ) {

                            System.out.println("Serveur, Veuillez saisir votre message");
                            R.setMessage(sc.nextLine()).encodeMessage();
                            out.write(R.getMessage().length);
                            out.write(R.getMessage());


                            System.out.println("Serveur, en attente du message du client");
                            size = in.read();
                            R.receiveMessage(in.readNBytes(size)).decodeMessage().readMessage();

                            if( in.equals("stop") ) {
                                break;
                            }

                        }

                        /** ON FERME LA SOCKET et les flux de lecture et écriture */
                        in.close();
                        out.close();
                        sockcli.close();

                } catch (IOException ex) {

                    ex.printStackTrace();

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        } finally {

            try {
                sockserv.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

}


