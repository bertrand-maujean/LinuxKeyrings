


/**
 * Wrapper pour les syscall key rings de Linux
 * Les keyrings sont représentés par des "int" = int32 signés
 * -1 est la valeur de retour d'erreur, donc pas un keyring vlable
 * 
 */


//import java.util.Map;
//import java.lang.RuntimeException;

import java.nio.charset.StandardCharsets;

public class LinuxKeyrings {

    /**
     * Chargement de la librairie .so
     */
    static {
        //System.loadLibrary("LinuxKeyrings");
        System.load("/home2/ber/projetsDev/linuxKeyrings250/bin/LinuxKeyrings.so");
    }
    

    /**
     * Constantes à utiliser avec getKeyringId() pour récupérer les keyrings prédéfinis du systèmes
     */
    public static final int  KEY_SPEC_THREAD_KEYRING        = -1;  //    key ID for thread-specific keyring
    public static final int  KEY_SPEC_PROCESS_KEYRING       = -2;  //    key ID for process-specific keyring
    public static final int  KEY_SPEC_SESSION_KEYRING       = -3;  //    key ID for session-specific keyring
    public static final int  KEY_SPEC_USER_KEYRING          = -4;  //    key ID for UID-specific keyring
    public static final int  KEY_SPEC_USER_SESSION_KEYRING  = -5;  //    key ID for UID-session keyring
    public static final int  KEY_SPEC_GROUP_KEYRING         = -6;  //    key ID for GID-specific keyring
    public static final int  KEY_SPEC_REQKEY_AUTH_KEY       = -7;  //    key ID for assumed request_key auth key
    public static final int  KEY_SPEC_REQUESTOR_KEYRING     = -8;  //    key ID for request_key() dest keyring


    /** getKeyringId()
     * Renvoie un des keyrings préexistant
     * Wrapper pour : KEYCTL_GET_KEYRING_ID / KEY_SPEC_THREAD_KEYRING This specifies the calling thread's thread-specific keyring.
     * @return int décrivant le keyring, ou null si non trouvé
     */
    public static int getKeyringId(int krid) {
        return doGetKeyringId(krid);
    }; 
    private static native int doGetKeyringId(int specialId);



    /** addKey()
     * @param type
     * @param description
     * @param payload
     * @param keyring
     * @return
     */
    public static int addKey(String type, String description, byte[] payload, int keyring) {
        byte[] bType        = (type+"\0").getBytes(StandardCharsets.UTF_8);
        byte[] bdescription = (description+"\0").getBytes(StandardCharsets.UTF_8);
        int result = doAddKey(bType, bdescription, payload, keyring);
        return result;
    };
    private static native int doAddKey(byte[] type, byte[] description, byte[] payload, int keyring);


    /** update()
     * 
     * Wrapper pour : 
     *   int sys_keyctl( KEYCTL_UPDATE, key_serial_t cleAUpdater, void * nouveauPayload, size_t nouveauPayloadSize) 
     */
    public static int update(int key, byte[] nouveauPayload) {
        return doUpdate(key, nouveauPayload);
    }
    private static native int doUpdate(int key, byte[] nouveauPayload);


    /** read()
     * 
     * Wrapper pour :
     *   size_t sys_keyctl(KEYCTL_READ, key_serial_t key, char * buffer, size_t bufferLen) valeur de retour = len payload lu 
     * 
     * Note : renvoie null si erreur
     * Dans ce cas, code d'erreur à récupérer autrememnt : TODO
     */
    public static byte[] read(int key) {
        int tailleBuffer = 32;
        int nbLus;
        byte[] buffer;
        do {
            tailleBuffer = tailleBuffer*2;
            buffer = new byte[tailleBuffer];
            nbLus = doRead(key, buffer);
            if (nbLus < 0)              return null;
            if (tailleBuffer > (1<<19)) return null;
        } while (nbLus >= tailleBuffer);
        return buffer;
    }
    private static native int doRead(int key, byte[] resultBuffer);


    /** link() 
     * 
     * Wrapper de : 
     *   sys_keyctl(KEYCTL_LINK, key_serial_t keyToLink, key_serial_t keyringToLinkTo)
     *   Create a link from a keyring to a key
     */
    public static int link(int keyToLink, int keyringToLinkTo) {
        return doKeyCtlAllInt(8 /*KEYCTL_LINK*/, keyToLink, keyringToLinkTo, 0, 0);
    }; /* link()  */
    private static native int doKeyCtlAllInt(int function, int arg2, int arg3, int arg4, int arg5);

    
    /** unlink()
     * Wrapper de :    
     *   sys_keyctl(KEYCTL_UNLINK, key_serial_t keyToLink, key_serial_t keyringToUnkinkFrom)
     *   Unlink a key from a keyring.
     */
    public static int unlink(int keyToLink, int keyringToUnlinkFrom) {
        return doKeyCtlAllInt(9 /*KEYCTL_UNLINK*/, keyToLink, keyringToUnlinkFrom, 0, 0);
    }; /* unlink() */


    /** clear()
     * Wrapper pour :
     *   sys_keyctl(KEYCTL_CLEAR, int keyring)
     *   Clear the contents
     */
    public static int clear(int keyring) {
        return doKeyCtlAllInt(7 /*KEYCTL_CLEAR*/, keyring, 0, 0, 0);
    }
    
    
    /** requestKey()
     * @param type
     * @param description
     * @param calloutInfo
     * @param destKeyring
     * @return
     */
    public static int requestKey(String type, String description, String calloutInfo, int destKeyring) {
        throw new java.lang.RuntimeException("Not implemented");
    };
    
    /**
     * KEYCTL_SEARCH Search for a key in a keyring tree, returning its ID and optionally linking it to a specified keyring.
     * @return LinuxKey la clé trouvée, ou null si non trouvée
     */
    public static int search(int baseKeyring, String typeStr, String descrStr, int linkTo) {
        throw new java.lang.RuntimeException("Not implemented");

    }; /* search() */
    private static native int doSearch(int baseKeyring, byte[] typeBytes, byte[] descrBytes, int linkTo);
    

    /** invalidate()
     * Wrapper pour sys_keyctl(KEYCTL_INVALIDATE, key)
     * @param key
     * @return
     */
    public static int invalidate(int key) {
        return doKeyCtlAllInt( /*KEYCTL_INVALIDATE*/ 21, key, 0, 0, 0);
    }
        

    /** setTimeout()
     * Wrapper pour sys_keyctl(KEYCTL_SET_TIMEOUT, key_serial_t key, unsigned int timeout)
     */
    public static int setTimeout(int key, int timeout) {
        return doKeyCtlAllInt( /*KEYCTL_SET_TIMEOUT*/ 15, key, timeout, 0, 0);
    }


    /** describe()
     * Wrapper pour :
     *   Wrapper pour sys_keyctl(KEYCTL_DESCRIBE, key_serial_t key, char* descr, size_t descrMaxLen)
     */
    public static String describe(int key) {
        throw new java.lang.RuntimeException("Not implemented");
    }
    private static native int doDescribe(int key, byte[] descr);
    
    


    /**
     * Wrapper pour :  sys_keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perms)
    */
    public static int setPerm(int key) {
        // utiliser int doSyscallAllInt(int function, int arg2, int arg3, int arg4, int arg5);
        throw new java.lang.RuntimeException("Not implemented");
    }




   
    


@SuppressWarnings("unused")
private final String commentaire = """
KEYCTL_GET_KEYRING_ID       Map a special key ID to a real key ID for this process
KEYCTL_JOIN_SESSION_KEYRING /* Replace the session keyring this process subscribes to with a new session keyring. */
KEYCTL_UPDATE   /* Update a key's data payload. */
KEYCTL_REVOKE   /* Revoke  the key with the ID provided */
KEYCTL_CHOWN    /* Change the ownership (user and group ID) of a key */
KEYCTL_SETPERM  /* Change the permissions of the key with the ID provided */
KEYCTL_DESCRIBE /* Obtain a string describing the attributes of a specified key. */
KEYCTL_CLEAR    /* Clear the contents */
KEYCTL_LINK     /* Create a link from a keyring to a key */
KEYCTL_UNLINK   /* Unlink a key from a keyring. */
KEYCTL_SEARCH   /* Search for a key in a keyring tree, returning its ID and optionally linking it to a specified keyring. */
KEYCTL_READ     /* Read the payload data of a key. */
KEYCTL_INSTANTIATE        /* (Positively) instantiate an uninstantiated key with a specified payload */
KEYCTL_NEGATE             /* Negatively instantiate an uninstantiated key. */
KEYCTL_SET_REQKEY_KEYRING /* Set the default keyring to which implicitly requested keys will be linked for this thread, and return the previous setting */
KEYCTL_SET_TIMEOUT        /* Set a timeout on a key. */
KEYCTL_ASSUME_AUTHORITY   /* Assume (or divest) the authority for the calling thread to instantiate a key. */
KEYCTL_GET_SECURITY       /* Get the LSM (Linux Security Module) security label of the specified key */
KEYCTL_SESSION_TO_PARENT  /* Replace the session keyring to which the parent of the calling process subscribes with the session keyring of the calling process. */
KEYCTL_REJECT             /* Mark a key as negatively instantiated and set an expiration timer on the key. */
KEYCTL_INSTANTIATE_IOV    /* Instantiate an uninstantiated key with a payload specified via a vector of buffers */
KEYCTL_INVALIDATE         /* Mark a key as invalid. */
KEYCTL_GET_PERSISTENT     /* Get the persistent keyring (persistent-keyring(7)) for a specified user and link it to a specified keyring. */
KEYCTL_DH_COMPUTE         /* Compute a Diffie-Hellman shared secret or public key */
KEYCTL_RESTRICT_KEYRING   /* Apply  a key-linking restriction to the keyring  */

248	sys_add_key	(const char *_type	const char *_description	const void *_payload	size_t plen		)
249	sys_request_key	(const char *_type	const char *_description	const char *_callout_info	key_serial_t destringid		)
250	sys_keyctl ( * )

""";

};
