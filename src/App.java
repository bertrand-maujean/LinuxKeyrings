import java.nio.charset.StandardCharsets;

public class App {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello, World!");

        int r = LinuxKeyrings.getKeyringId(LinuxKeyrings.KEY_SPEC_USER_KEYRING);
        System.out.println("KEY_SPEC_USER_KEYRING = " +r);



        String payloadString = "l353cRe1-2";
        byte[] payloadBytes  = payloadString.getBytes(StandardCharsets.UTF_8);
        

        int k = LinuxKeyrings.addKey("user", "test Bertand 2", payloadBytes, r /* LinuxKeyrings.KEY_SPEC_USER_KEYRING*/);
        System.out.println("Clé ajouté en = " +k);



        byte[] result = LinuxKeyrings.read(k);
        System.out.println("result ="+result);


    }
}
