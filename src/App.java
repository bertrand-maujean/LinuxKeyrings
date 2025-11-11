import java.nio.charset.StandardCharsets;

public class App {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello, World!");

        LinuxKeyrings.initLibFilename("/home2/ber/projetsDev/LinuxKeyrings/bin/LinuxKeyrings.so");


        int userKR = LinuxKeyrings.getKeyringId(LinuxKeyrings.KEY_SPEC_USER_KEYRING);
        System.out.println("KEY_SPEC_USER_KEYRING = " +userKR);

        String payloadString = "l353cRe1-2";
        byte[] payloadBytes  = payloadString.getBytes(StandardCharsets.UTF_8);
        
        int k = LinuxKeyrings.addKey("user", "Hello keyrings", payloadBytes, userKR /* LinuxKeyrings.KEY_SPEC_USER_KEYRING*/);
        System.out.println("Clé ajouté en = " +k);


        int k2 = LinuxKeyrings.addKey("user", "Other", payloadBytes, userKR /* LinuxKeyrings.KEY_SPEC_USER_KEYRING*/);
        System.out.println("keyctl_describe = "+LinuxKeyrings.describe(k2));

        byte[] result = LinuxKeyrings.read(k);
        System.out.println("result ="+new String(result));
        System.out.println("keyctl_describe = "+LinuxKeyrings.describe(k));
        
        System.out.println("\nEssai de listage d'un keyring :");
        int[] liste = LinuxKeyrings.readKeyring(userKR);
        for (int i=0; i<liste.length; i++) {
            System.out.println("\t"+liste[i]+"\t"+LinuxKeyrings.describe(liste[i]));
        }

    }
}
