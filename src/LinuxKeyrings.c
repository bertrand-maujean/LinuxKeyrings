/*
Se compile par un truc du genre :

gcc -fPIC -shared -nostartfiles -o Linuxkeyrings.so 
   -I /usr/lib/jvm/java-21-openjdk-amd64/include/ LinuxKeyrings.c  
   -I /usr/lib/jvm/java-21-openjdk-amd64/include/linux/

Les répertoires d'includes sont dans le chemin d'install de java, pas par défaut

Note /usr/include/keyutils.h : typedef int32_t key_serial_t;

*/


/* Includes syscall */
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>
#include <keyutils.h>

/* Includes libc */
//#include <string.h>

/* Includes spécifiques au projet */
#include <jni.h>
#include "LinuxKeyrings.h"   /* Fichier auto généré par "javac -h . LinuxKeyrings.java"  */
#include <jni_md.h>


/* Includes locaux */








JNIEXPORT jint JNICALL Java_LinuxKeyrings_doAddKey
  (JNIEnv *jniEnv, jclass, jbyteArray jKeyType, jbyteArray jDescription, jbyteArray jPayload, jint keyring) {

    /*
     Signature des fonctions en java et syscall :
      private static native long doAddKey(byte[] type, byte[] description, byte[] payload, int payloadLen, long keyring);
      sys_add_key	(const char *_type	const char *_description	const void *_payload	size_t plen  key_serial_t keyring);
    */

    /* Récupération des adresses mémoire des tableaux d'octets  */
    jbyte* bKeyType     = (*jniEnv)->GetByteArrayElements(jniEnv, jKeyType,      NULL);  /* isCopy n'est pas utile pour nous  */
    jbyte* bDescription = (*jniEnv)->GetByteArrayElements(jniEnv, jDescription,  NULL);
    jbyte* bPayload     = (*jniEnv)->GetByteArrayElements(jniEnv, jPayload,      NULL);  

    int    payloadLen   = (*jniEnv)->GetArrayLength(jniEnv, jPayload);

    /* Le syscall  */
    int r = syscall(SYS_add_key,  bKeyType,  bDescription,  bPayload,  payloadLen,  keyring) ;
    if (r == -1) {
      perror("sys_add_key() ");
    }

    /* Informe la JVM qu'on a terminé avec les tableaux d'octets en mémoire, sans resynchro vers la JVM pour cet appel là  */
    (*jniEnv)->ReleaseByteArrayElements(jniEnv, jKeyType,     bKeyType,     JNI_ABORT); /* abort = pas de recopie de données dans l'autre sens, inutile ici  */
    (*jniEnv)->ReleaseByteArrayElements(jniEnv, jDescription, bDescription, JNI_ABORT); /* abort = pas de recopie de données dans l'autre sens, inutile ici  */   
    (*jniEnv)->ReleaseByteArrayElements(jniEnv, jPayload,     bPayload,     JNI_ABORT); /* abort = pas de recopie de données dans l'autre sens, inutile ici  */
    return r;
  }



JNIEXPORT jint JNICALL Java_LinuxKeyrings_doGetKeyringId (JNIEnv *, jclass, jint krid) {
    int r = syscall(SYS_keyctl,  KEYCTL_GET_KEYRING_ID,  krid);
    return r;
  }






JNIEXPORT jint JNICALL Java_LinuxKeyrings_doKeyCtlAllInt
  (JNIEnv *, jclass, jint function, jint arg2, jint arg3, jint arg4, jint arg5) {
    // private static native int doSyscallAllInt(int function, int arg2, int arg3, int arg4, int arg5);
    return syscall(function, arg2, arg3, arg4, arg5);
  }

JNIEXPORT jint JNICALL Java_LinuxKeyrings_doUpdate
  (JNIEnv *jniEnv, jclass, jint key, jbyteArray jNouveauPayload) {
    // private static native int doUpdate(int key, byte[] nouveauPayload);

    jbyte* bPayload     = (*jniEnv)->GetByteArrayElements(jniEnv, jNouveauPayload, NULL); 
    int    payloadLen   = (*jniEnv)->GetArrayLength(jniEnv, jNouveauPayload);
    return syscall(KEYCTL_UPDATE,  key,  bPayload,  payloadLen);
  }


JNIEXPORT jint JNICALL Java_LinuxKeyrings_doRead
  (JNIEnv *jniEnv, jclass, jint key, jbyteArray resultBuffer) {
    // private static native int doRead(int key, byte[] resultBuffer);
    jbyte* bResult   = (*jniEnv)->GetByteArrayElements(jniEnv, resultBuffer, NULL);
    jsize  resultLen = (*jniEnv)->GetArrayLength(jniEnv, resultBuffer);

    ssize_t payloadLen = syscall(SYS_keyctl, KEYCTL_READ, key, bResult, resultLen);
    if (payloadLen < 0) {
        /* libère le buffer sans recopier (rien de valable à copier) */
        (*jniEnv)->ReleaseByteArrayElements(jniEnv, resultBuffer, bResult, JNI_ABORT);
        return payloadLen;
    }

    /* Si on a utilisé GetByteArrayElements, laisser Release copier les données vers Java */
    (*jniEnv)->ReleaseByteArrayElements(jniEnv, resultBuffer, bResult, 0); /* 0 -> copy back */

    return (jint)payloadLen;
  }
  

  JNIEXPORT jint JNICALL Java_LinuxKeyrings_doDescribe
  (JNIEnv *jniEnv, jclass, jint key, jbyteArray resultBuffer) {

    // private static native int doDescribe(int key, byte[] descr);

    jbyte* bResult   = (*jniEnv)->GetByteArrayElements(jniEnv, resultBuffer, NULL);
    jsize  resultLen = (*jniEnv)->GetArrayLength(jniEnv, resultBuffer);

    ssize_t payloadLen = syscall(SYS_keyctl, KEYCTL_DESCRIBE, key, bResult, resultLen);
    if (payloadLen < 0) {
        /* libère le buffer sans recopier (rien de valable à copier) */
        (*jniEnv)->ReleaseByteArrayElements(jniEnv, resultBuffer, bResult, JNI_ABORT);
        return payloadLen;
    }

    /* Si on a utilisé GetByteArrayElements, laisser Release copier les données vers Java */
    (*jniEnv)->ReleaseByteArrayElements(jniEnv, resultBuffer, bResult, 0); /* 0 -> copy back */

    return (jint)payloadLen;
  }



JNIEXPORT jint JNICALL Java_LinuxKeyrings_doSearch
  (JNIEnv *jniEnv, jclass, jint baseKeyring, jbyteArray jType, jbyteArray jDescr, jint linkTo) {
    // private static native int doSearch(int baseKeyring, byte[] typeBytes, byte[] descrBytes, int linkTo);
    jbyte* bType  = (*jniEnv)->GetByteArrayElements(jniEnv, jType,  NULL);
    jbyte* bDescr = (*jniEnv)->GetByteArrayElements(jniEnv, jDescr, NULL);

    int result = syscall(SYS_keyctl, KEYCTL_SEARCH, baseKeyring, bType, bDescr, linkTo);

    (*jniEnv)->ReleaseByteArrayElements(jniEnv, jType,  bType,  JNI_ABORT);
    (*jniEnv)->ReleaseByteArrayElements(jniEnv, jDescr, bDescr, JNI_ABORT);

    return result;
  }


/*
gcc -I /usr/lib/jvm/java-17-openjdk-amd64/include -I /usr/lib/jvm/java-17-openjdk-amd64/include/linux

KEYCTL_GET_KEYRING_ID       Map a special key ID to a real key ID for this process
KEYCTL_JOIN_SESSION_KEYRING  Replace the session keyring this process subscribes to with a new session keyring. 
KEYCTL_UPDATE   Update a key's data payload. 
KEYCTL_REVOKE    Revoke  the key with the ID provided 
KEYCTL_CHOWN     Change the ownership (user and group ID) of a key 
KEYCTL_SETPERM   Change the permissions of the key with the ID provided 
KEYCTL_DESCRIBE  Obtain a string describing the attributes of a specified key. 
KEYCTL_CLEAR     Clear the contents 
KEYCTL_LINK      Create a link from a keyring to a key 
KEYCTL_UNLINK    Unlink a key from a keyring. 
KEYCTL_SEARCH    Search for a key in a keyring tree, returning its ID and optionally linking it to a specified keyring. 
KEYCTL_READ      Read the payload data of a key. 
KEYCTL_INSTANTIATE         (Positively) instantiate an uninstantiated key with a specified payload 
KEYCTL_NEGATE              Negatively instantiate an uninstantiated key. 
KEYCTL_SET_REQKEY_KEYRING  Set the default keyring to which implicitly requested keys will be linked for this thread, and return the previous setting 
KEYCTL_SET_TIMEOUT         Set a timeout on a key. 
KEYCTL_ASSUME_AUTHORITY    Assume (or divest) the authority for the calling thread to instantiate a key. 
KEYCTL_GET_SECURITY        Get the LSM (Linux Security Module) security label of the specified key 
KEYCTL_SESSION_TO_PARENT   Replace the session keyring to which the parent of the calling process subscribes with the session keyring of the calling process. 
KEYCTL_REJECT              Mark a key as negatively instantiated and set an expiration timer on the key. 
KEYCTL_INSTANTIATE_IOV     Instantiate an uninstantiated key with a payload specified via a vector of buffers 
KEYCTL_INVALIDATE          Mark a key as invalid. 
KEYCTL_GET_PERSISTENT      Get the persistent keyring (persistent-keyring(7)) for a specified user and link it to a specified keyring. 
KEYCTL_DH_COMPUTE          Compute a Diffie-Hellman shared secret or public key 
KEYCTL_RESTRICT_KEYRING    Apply  a key-linking restriction to the keyring  

248	sys_add_key	(const char *_type	const char *_description	const void *_payload	size_t plen		)
249	sys_request_key	(const char *_type	const char *_description	const char *_callout_info	key_serial_t destringid		)
250	long syscall(SYS_keyctl, int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

#define SYS_keyctl
#define SYS_request_key
#define SYS_add_key

*/
