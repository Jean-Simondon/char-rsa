import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * La classe GestionnaireCryptage est utile à manipuler toutes les fonctions de crypage, décryptage et génération de clef
 * Selon la classe qui le manipule, on lui donne le rôle d'émetteur ou récepteur afin que le code du constructeur s'adapte en fonction
 * Si Récepteur : Génération de clefs RSA
 * Si Emetteur : Génération de clef secrète
 */
public class GestionnaireCryptage {

/** --------------------------------------------------------------------------------------------------- **\
                                     ATTRIBUT
\** --------------------------------------------------------------------------------------------------- **/

    public static final String TAG = "GestionnaireCryptage";

    /**
     * La paire de clef RSA
     */
    private PublicKey publicKey; // clef public RSA
    private PrivateKey privateKey; // clef privée RSA

    /**
     * Usage de Cipher pour coder ou décoder des messages encrypté en DES
     */
    private Cipher cipherEncrypt; // utile à coder le message puis sa clef secrète
    private Cipher cipherDeCrypt; // un cipher pour décriper le message qui viendra

    /**
     * Le message dans sa version chaine de caractère ou tableau de bytes
     */
    private String messageEnChar; // le message en chaine de caractère
    private byte[] messageEnByte; // le même message en byte code qu'envoie l'émetteur et qui sera à décoder

    /**
     * La clef secrète, générée par l'émetteur et reçut ici
     */
    private Key secretKey; // la clef secrète que va envoyer l'émetteur et qui sera à décoder
    private byte[] secretKeyByte;

/** --------------------------------------------------------------------------------------------------- **\
                                 CONSTRUCTEUR
\** --------------------------------------------------------------------------------------------------- **/

    /**
     * Le Gestionnaire De Cryptage est utile à tout processus souhaitant communiqué en RSA
     * Il faut tout de même se choisir le rôle de émetteur ou récepteur afin de savoir qui génère le couple de clef RSA et qui génère la clef secrète
     * afin de gérer ces rôles, cela se passe dans le constructeur en envoyant une chaine de caractère comme argument pour choisir
     * @param role emetteur (demande une clef publique puis envoi la clef secrète) ou recepteur (génère clef RSA et reçoit clef secrète encodée)
     * @param proto RSA
     * @throws Exception
     */
    public GestionnaireCryptage(String role, String proto) throws Exception
    {
        if( role.equals("emetteur")) {

            /** Génération de la clef secrète et encodage */
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(56);
            secretKey = keyGen.generateKey();
            secretKeyByte = secretKey.getEncoded();

        } else if ( role.equals("recepteur")) {

            /** Génération des clefs publique et privée */
            KeyPairGenerator KPG = KeyPairGenerator.getInstance(proto); /** active le générateur de clef RSA */
            KPG.initialize(1024); /** initialise la longueur des clés */
            KeyPair keypair = KPG.genKeyPair(); /** génère les clefs */

            publicKey = keypair.getPublic(); /** on récupère la clef public */
            privateKey = keypair.getPrivate(); /** on récupère la clef public */
        }

        cipherDeCrypt = Cipher.getInstance(proto); /** on a besoin d'un cipher pour décrypter le message */

    }

/** --------------------------------------------------------------------------------------------------- **\
                                 FONCTION UTILE UTILE A L'EMETTEUR
\** --------------------------------------------------------------------------------------------------- **/

    /**
     * Réception de la clef secrète
     * @param p
     */
    public void setPublicKey(byte[] p)
    {
        X509EncodedKeySpec ks = new X509EncodedKeySpec(p);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            this.publicKey = kf.generatePublic(ks);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
     * Encodage de la clef secrète à l'aide de la clef publique
     * @throws Exception
     */
    public void encodeSecretKey() throws Exception
    {
        cipherEncrypt = Cipher.getInstance("RSA");
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey);
        secretKeyByte = cipherEncrypt.doFinal(secretKeyByte);
    }

    /**
     * Envoi de la clef secrète
     * @return
     */
    public byte[] sendSecretKey()
    {
        return this.secretKeyByte;
    }


/** ------------------------------------------------------------------------------------ **\
                             FOCNTION UTILE UTILE AU RECEPTEUR
\** ------------------------------------------------------------------------------------ **/

    /**
     * @return Renvoie la clef publique
     */
    public PublicKey getPublicKey ()
    {
        return this.publicKey;
    }

    /**
     * initialise l'attribut clef secrète
     * @param k la clef re!ut en tableau de byte
     */
    public void setSecretKey(byte[] k)
    {
        this.secretKeyByte = k;
    }

    /**
     * décodage de la clef secrète
     * @throws Exception
     */
    public void decodeSecretKey() throws Exception
    {
        cipherDeCrypt = Cipher.getInstance("RSA");
        cipherDeCrypt.init(Cipher.DECRYPT_MODE, privateKey);
        secretKeyByte = cipherDeCrypt.doFinal(secretKeyByte);
        this.secretKey = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, "DES");
    }

 /** ------------------------------------------------------------------------------------ **\
           FONCTION RELATIVE AU MESSAGE ET UTILE A L'EMETTEUR COMME AU RECEPTEUR
 \** ------------------------------------------------------------------------------------ **/

    /**
     * Réception d'un message en bytes
     * @param m
     */
    public GestionnaireCryptage receiveMessage(byte[] m)
    {
        this.messageEnByte = m;
        return this;
    }

    /**
     * Initialisation du message
     * @param m
     */
    public GestionnaireCryptage setMessage(String m)
    {
        this.messageEnChar = m;
        this.messageEnByte = m.getBytes();
        return this;
    }

    /**
     * Récupératon du message par la classe utilisatrice
     * @return
     */
    public byte[] getMessage()
    {
        return this.messageEnByte;
    }

    /**
     * Encodage d'un message avant son envoi
     * @throws Exception
     */
    public void encodeMessage() throws Exception
    {
        cipherEncrypt = Cipher.getInstance("DES");
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, secretKey);
        messageEnByte = cipherEncrypt.doFinal(messageEnByte);
    }

    /**
     * Décodage du message après réception
     * @throws Exception
     */
    public GestionnaireCryptage decodeMessage() throws Exception
    {
        cipherDeCrypt = Cipher.getInstance("DES");
        cipherDeCrypt.init(Cipher.DECRYPT_MODE, secretKey);
        messageEnByte = cipherDeCrypt.doFinal(messageEnByte);
        messageEnChar = new String(messageEnByte);
        return this;
    }

    /**
     * Lecture du message sur la sortie standard
     */
    public void readMessage()
    {
        System.out.println("Le correspondant dit : " + messageEnChar);
    }

}
