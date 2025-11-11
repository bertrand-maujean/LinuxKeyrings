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

    /** initialization of JNI external .so file
     * One of the two methods must be call before any other
     */
    public static void initLib(String libname) {
        System.loadLibrary(libname);
    }

    public static void initLibFilename(String filename) {
        System.load(filename);
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

    /**
     * Constantes à utiliser avec setPerm() pour fixer les droits
     * Notes :
     * - extrait de /usr/include/keyutils.h 
     * - rien avec bit 31 à 1 => le type int convient encore
     */
    public static final int  KEY_POS_VIEW    = 0x01000000;      /* possessor can view a key's attributes */
    public static final int  KEY_POS_READ    = 0x02000000;      /* possessor can read key payload / view keyring */
    public static final int  KEY_POS_WRITE   = 0x04000000;      /* possessor can update key payload / add link to keyring */
    public static final int  KEY_POS_SEARCH  = 0x08000000;      /* possessor can find a key in search / search a keyring */
    public static final int  KEY_POS_LINK    = 0x10000000;      /* possessor can create a link to a key/keyring */
    public static final int  KEY_POS_SETATTR = 0x20000000;      /* possessor can set key attributes */
    public static final int  KEY_POS_ALL     = 0x3f000000;

    public static final int  KEY_USR_VIEW    = 0x00010000;      /* user permissions... */
    public static final int  KEY_USR_READ    = 0x00020000;
    public static final int  KEY_USR_WRITE   = 0x00040000;
    public static final int  KEY_USR_SEARCH  = 0x00080000;
    public static final int  KEY_USR_LINK    = 0x00100000;
    public static final int  KEY_USR_SETATTR = 0x00200000;
    public static final int  KEY_USR_ALL     = 0x003f0000;

    public static final int  KEY_GRP_VIEW    = 0x00000100;     /* group permissions... */
    public static final int  KEY_GRP_READ    = 0x00000200;
    public static final int  KEY_GRP_WRITE   = 0x00000400;
    public static final int  KEY_GRP_SEARCH  = 0x00000800;
    public static final int  KEY_GRP_LINK    = 0x00001000;
    public static final int  KEY_GRP_SETATTR = 0x00002000;
    public static final int  KEY_GRP_ALL     = 0x00003f00;

    public static final int  KEY_OTH_VIEW    = 0x00000001;     /* third party permissions... */
    public static final int  KEY_OTH_READ    = 0x00000002;
    public static final int  KEY_OTH_WRITE   = 0x00000004;
    public static final int  KEY_OTH_SEARCH  = 0x00000008;
    public static final int  KEY_OTH_LINK    = 0x00000010;
    public static final int  KEY_OTH_SETATTR = 0x00000020;
    public static final int  KEY_OTH_ALL     = 0x0000003f;


    /** getKeyringId()
     * Renvoie un des keyrings préexistant
     * Wrapper pour : KEYCTL_GET_KEYRING_ID / KEY_SPEC_THREAD_KEYRING This specifies the calling thread's thread-specific keyring.
     * @return int décrivant le keyring, ou null si non trouvé
     */
    public static int getKeyringId(int krid) throws ErrnoException {
        int result = doGetKeyringId(krid);
        if (result<0) {
            throw new ErrnoException(-result);
        }  
        return result; 
    }; 
    private static native int doGetKeyringId(int specialId);



    /** addKey()
     * @param type
     * @param description
     * @param payload
     * @param keyring
     * @return
     */
    public static int addKey(String type, String description, byte[] payload, int keyring) throws ErrnoException {
        byte[] bType        = (type+"\0").getBytes(StandardCharsets.UTF_8);
        byte[] bdescription = (description+"\0").getBytes(StandardCharsets.UTF_8);
        int result = doAddKey(bType, bdescription, payload, keyring);
        if (result<0) {
            throw new ErrnoException(-result);
        }          
        return result;
    };
    private static native int doAddKey(byte[] type, byte[] description, byte[] payload, int keyring);


    /** update()
     * 
     * Wrapper pour : 
     *   int sys_keyctl( KEYCTL_UPDATE, key_serial_t cleAUpdater, void * nouveauPayload, size_t nouveauPayloadSize) 
     */
    public static void update(int key, byte[] nouveauPayload) throws ErrnoException {
        int result = doUpdate(key, nouveauPayload);
        if (result<0) {
            throw new ErrnoException(-result);
        }         
    }
    private static native int doUpdate(int key, byte[] nouveauPayload);


    /** read()
     * 
     * Wrapper pour :
     *   size_t sys_keyctl(KEYCTL_READ, key_serial_t key, char * buffer, size_t bufferLen) valeur de retour = len payload lu 
     * 
     * Note : renvoie null si erreur
     * Dans ce cas, code d'erreur à récupérer autrememnt : TODO
     * 
     * 
     * Note : le syscall renvoie la longueur totale de la clé, mais n'en copie qu'à concurrence de la taille du buffer
     * 
     */
    public static byte[] read(int key) throws ErrnoException {
        int payloadLen;
        int tailleBuffer=80;
        byte[] buffer = new byte[tailleBuffer];

        payloadLen = doRead(key, buffer);        
        if (payloadLen < 0) {
            throw new ErrnoException(-payloadLen);
        }

        if (payloadLen > tailleBuffer) {
            // Recommence : le buffer n'était pas assez grand
            tailleBuffer = payloadLen;
            buffer = new byte[tailleBuffer];
            payloadLen = doRead(key, buffer);
            if (payloadLen < 0) {
                throw new ErrnoException(-payloadLen);
            }
        }

        byte[] result = new byte[payloadLen];
        for (int i=0; i<payloadLen; i++) {
            result[i] = buffer[i];
        }

        return result;
    }
    private static native int doRead(int key, byte[] resultBuffer);


    /**
     * Get key list from a given keyring
     * Special : may throw ErrnoException even if it's not directly a syscall error. 
     *   In this case, we assume that the given key was not a keyring, so EINVAL is relevant
     * 
     * Note : should fail on big endian systems, if some still exist in the wild
     * 
     * @param key
     * @return
     * @throws ErrnoException
     */
    public static int[] readKeyring(int key) throws ErrnoException {
        /* Utilise read() et converti le bloc byte[] reçu en int[] des key contenues, voir man 2 keyctl/KEYCTL_READ */

        byte[] bytes = read(key);

        if ( bytes.length % 4 !=0) {
            throw new ErrnoException( ErrnoException.EINVAL );
        }
        int nbKeys = bytes.length >> 2;
        int[] result = new int[nbKeys];
        for (int i=0; i< nbKeys; i++) {
            result[i] = 0;
            for (int p=0; p<4; p++) {
                result[i] += (((int)bytes[p + 4*i]) & 0xff) << (p*8);
            }
        }
        return result;
    }
    

    /** link() 
     * 
     * Wrapper de : 
     *   sys_keyctl(KEYCTL_LINK, key_serial_t keyToLink, key_serial_t keyringToLinkTo)
     *   Create a link from a keyring to a key
     */
    public static void link(int keyToLink, int keyringToLinkTo) throws ErrnoException {
        int result = doKeyCtlAllInt(8 /*KEYCTL_LINK*/, keyToLink, keyringToLinkTo, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }            
    }; /* link()  */
    private static native int doKeyCtlAllInt(int function, int arg2, int arg3, int arg4, int arg5);

    
    /** unlink()
     * Wrapper de :    
     *   sys_keyctl(KEYCTL_UNLINK, key_serial_t keyToLink, key_serial_t keyringToUnkinkFrom)
     *   Unlink a key from a keyring.
     */
    public static void unlink(int keyToLink, int keyringToUnlinkFrom) throws ErrnoException {
        int result = doKeyCtlAllInt(9 /*KEYCTL_UNLINK*/, keyToLink, keyringToUnlinkFrom, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }            
    }; /* unlink() */


    /** clear()
     * Wrapper pour :
     *   sys_keyctl(KEYCTL_CLEAR, int keyring)
     *   Clear the contents
     */
    public static void clear(int keyring) throws ErrnoException {
        int result = doKeyCtlAllInt(7 /*KEYCTL_CLEAR*/, keyring, 0, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }            
    }
    

    /** invalidate()
     * Wrapper pour sys_keyctl(KEYCTL_INVALIDATE, key)
     * @param key
     * @return
     */
    public static void invalidate(int key) throws ErrnoException {
        int result = doKeyCtlAllInt( /*KEYCTL_INVALIDATE*/ 21, key, 0, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }                
    }
        

    /** setTimeout()
     * Wrapper pour sys_keyctl(KEYCTL_SET_TIMEOUT, key_serial_t key, unsigned int timeout)
     */
    public static void setTimeout(int key, int timeout) throws ErrnoException {
        int result = doKeyCtlAllInt( /*KEYCTL_SET_TIMEOUT*/ 15, key, timeout, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }
    }


    /** describe()
     * Wrapper pour :
     *   Wrapper pour sys_keyctl(KEYCTL_DESCRIBE, key_serial_t key, char* descr, size_t descrMaxLen)
     */
    public static String describe(int key) throws ErrnoException {
        int descriptionLen;
        int tailleBuffer=160;
        byte[] buffer = new byte[tailleBuffer];

        descriptionLen = doDescribe(key, buffer);        
        if (descriptionLen < 0) {
            throw new ErrnoException(-descriptionLen);
        }

        if (descriptionLen > tailleBuffer) {
            // Recommence : le buffer n'était pas assez grand
            tailleBuffer = descriptionLen;
            buffer = new byte[tailleBuffer];
            descriptionLen = doDescribe(key, buffer);
            if (descriptionLen < 0) {
                throw new ErrnoException(-descriptionLen);
            }
        }

        byte[] result = new byte[descriptionLen];
        for (int i=0; i<descriptionLen; i++) {
            result[i] = buffer[i];
        }

        return new String(result, StandardCharsets.UTF_8) ;
    }
    private static native int doDescribe(int key, byte[] descr);
   

    /**
     * Wrapper pour :  sys_keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perms)
     */
    public static void setPerm(int key, int perm) throws ErrnoException {
        int result = doKeyCtlAllInt(/*KEYCTL_SETPERM*/5 , key, perm, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }
    }


    /** revoke(int key)
     * Wrapper pour :  sys_keyctl(KEYCTL_REVOKE (3) )
     */
    public void revoke(int key) throws ErrnoException {
        int result = doKeyCtlAllInt(/*KEYCTL_REVOKE*/3 , key, 0, 0, 0);
        if (result<0) {
            throw new ErrnoException(-result);
        }        
    }



    /**
     * KEYCTL_SEARCH Search for a key in a keyring tree, returning its ID and optionally linking it to a specified keyring.
     * @return LinuxKey la clé trouvée, ou null si non trouvée
     */
    public static int search(int baseKeyring, String typeStr, String descrStr, int linkTo) throws ErrnoException {
        byte[] typeBytes  = typeStr.getBytes(StandardCharsets.UTF_8);
        byte[] descrBytes = descrStr.getBytes(StandardCharsets.UTF_8);
        int result = doSearch(baseKeyring, typeBytes, descrBytes, linkTo);
        if (result < 0) {
            throw new ErrnoException(-result);
        }
        return result;
    } /* search() */
    private static native int doSearch(int baseKeyring, byte[] typeBytes, byte[] descrBytes, int linkTo);    

    
       
    /** requestKey()
     * @param type
     * @param description
     * @param calloutInfo
     * @param destKeyring
     * @return
     */
    public static int requestKey(String type, String description, String calloutInfo, int destKeyring) {
        throw new java.lang.RuntimeException("Not implemented");
    }
  
}


/*

Wrappers faits :
----------------
248	sys_add_key	(const char *_type	const char *_description	const void *_payload	size_t plen		)

KEYCTL_GET_KEYRING_ID Map a special key ID to a real key ID for this process
KEYCTL_UPDATE         Update a key's data payload. 
KEYCTL_REVOKE         Revoke  the key with the ID provided 
KEYCTL_SETPERM        Change the permissions of the key with the ID provided 
KEYCTL_DESCRIBE       Obtain a string describing the attributes of a specified key. 
KEYCTL_CLEAR          Clear the contents 
KEYCTL_LINK           Create a link from a keyring to a key 
KEYCTL_UNLINK         Unlink a key from a keyring. 
KEYCTL_SEARCH         Search for a key in a keyring tree, returning its ID and optionally linking it to a specified keyring. 
KEYCTL_READ           Read the payload data of a key. 
KEYCTL_SET_TIMEOUT    Set a timeout on a key. 
KEYCTL_INVALIDATE     Mark a key as invalid. 


Wrapper pas faits :
-------------------
KEYCTL_JOIN_SESSION_KEYRING Replace the session keyring this process subscribes to with a new session keyring.
KEYCTL_CHOWN                Change the ownership (user and group ID) of a key
KEYCTL_INSTANTIATE        (Positively) instantiate an uninstantiated key with a specified payload 
KEYCTL_NEGATE             Negatively instantiate an uninstantiated key. 
KEYCTL_SET_REQKEY_KEYRING Set the default keyring to which implicitly requested keys will be linked for this thread, and return the previous setting 
KEYCTL_ASSUME_AUTHORITY   Assume (or divest) the authority for the calling thread to instantiate a key. 
KEYCTL_GET_SECURITY       Get the LSM (Linux Security Module) security label of the specified key 
KEYCTL_SESSION_TO_PARENT  Replace the session keyring to which the parent of the calling process subscribes with the session keyring of the calling process. 
KEYCTL_REJECT             Mark a key as negatively instantiated and set an expiration timer on the key. 
KEYCTL_INSTANTIATE_IOV    Instantiate an uninstantiated key with a payload specified via a vector of buffers 
KEYCTL_GET_PERSISTENT     Get the persistent keyring (persistent-keyring(7)) for a specified user and link it to a specified keyring. 
KEYCTL_DH_COMPUTE         Compute a Diffie-Hellman shared secret or public key 
KEYCTL_RESTRICT_KEYRING   Apply  a key-linking restriction to the keyring  

249	sys_request_key	(const char *_type	const char *_description	const char *_callout_info	key_serial_t destringid		)
250	sys_keyctl ( * )

*/
