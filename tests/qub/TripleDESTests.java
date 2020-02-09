package qub;

public interface TripleDESTests
{
    static void test(TestRunner runner)
    {
        runner.testGroup(TripleDES.class, () ->
        {
            runner.testGroup("encrypt(BitArray,BitArray)", () ->
            {
                final Action3<String,String,String> encryptTest = (String message, String initializationVector, String expectedCiphertext) ->
                {
                    runner.test("with message " + Strings.quote(message) + " and initialization vector " + Strings.quote(initializationVector), (Test test) ->
                    {
                        final BitArray plaintextBits = BitArray.createFromHexString(message);
                        final BitArray initializationVectorBits = BitArray.createFromHexString(initializationVector);

                        final BitArray ciphertextBits = TripleDES.encrypt(initializationVectorBits, plaintextBits);
                        test.assertNotNull(ciphertextBits);
                        test.assertEqual(expectedCiphertext, ciphertextBits.toHexString());
                    });
                };

                encryptTest.run("8787878787878787", "0E329232EA6D0D73133457799BBCDFF1", "25392EDEC93C1CEE");
                encryptTest.run("0123456789ABCDEF", "0E329232EA6D0D73133457799BBCDFF1", "8A1FEBF13B930592");
                encryptTest.run("596F7572206C6970", "0E329232EA6D0D73133457799BBCDFF1", "7DD6F8EFF5CA974C");
                encryptTest.run("732061726520736D", "0E329232EA6D0D73133457799BBCDFF1", "DACD338E796C37BA");
                encryptTest.run("6F6F746865722074", "0E329232EA6D0D73133457799BBCDFF1", "FB291B4A11CE2A70");
                encryptTest.run("68616E2076617365", "0E329232EA6D0D73133457799BBCDFF1", "D5F544CD4BA6068C");
                encryptTest.run("6C696E650D0A0000", "0E329232EA6D0D73133457799BBCDFF1", "793ECD59F846615E");

                encryptTest.run("8787878787878787", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "25392EDEC93C1CEE");
                encryptTest.run("0123456789ABCDEF", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "8A1FEBF13B930592");
                encryptTest.run("596F7572206C6970", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "7DD6F8EFF5CA974C");
                encryptTest.run("732061726520736D", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "DACD338E796C37BA");
                encryptTest.run("6F6F746865722074", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "FB291B4A11CE2A70");
                encryptTest.run("68616E2076617365", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "D5F544CD4BA6068C");
                encryptTest.run("6C696E650D0A0000", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "793ECD59F846615E");

                encryptTest.run("8787878787878787", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "0000000000000000");
                encryptTest.run("0123456789ABCDEF", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "31AA59FEB64386A6");
                encryptTest.run("596F7572206C6970", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "C0999FDDE378D7ED");
                encryptTest.run("732061726520736D", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "727DA00BCA5A84EE");
                encryptTest.run("6F6F746865722074", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "47F269A4D6438190");
                encryptTest.run("68616E2076617365", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "D9D52F78F5358499");
                encryptTest.run("6C696E650D0A0000", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "828AC9B453E0E653");
            });

            runner.testGroup("decrypt(BitArray,BitArray)", () ->
            {
                final Action3<String,String,String> decryptTest = (String ciphertext, String initializationVector, String expectedPlaintext) ->
                {
                    runner.test("with ciphertext " + Strings.quote(ciphertext) + " and initialization vector " + Strings.quote(initializationVector), (Test test) ->
                    {
                        final BitArray ciphertextBits = BitArray.createFromHexString(ciphertext);
                        final BitArray initializationVectorBits = BitArray.createFromHexString(initializationVector);

                        final BitArray plaintextBits = TripleDES.decrypt(initializationVectorBits, ciphertextBits);
                        test.assertNotNull(plaintextBits);
                        test.assertEqual(expectedPlaintext, plaintextBits.toHexString());
                    });
                };

                decryptTest.run("25392EDEC93C1CEE", "0E329232EA6D0D73133457799BBCDFF1", "8787878787878787");
                decryptTest.run("8A1FEBF13B930592", "0E329232EA6D0D73133457799BBCDFF1", "0123456789ABCDEF");
                decryptTest.run("7DD6F8EFF5CA974C", "0E329232EA6D0D73133457799BBCDFF1", "596F7572206C6970");
                decryptTest.run("DACD338E796C37BA", "0E329232EA6D0D73133457799BBCDFF1", "732061726520736D");
                decryptTest.run("FB291B4A11CE2A70", "0E329232EA6D0D73133457799BBCDFF1", "6F6F746865722074");
                decryptTest.run("D5F544CD4BA6068C", "0E329232EA6D0D73133457799BBCDFF1", "68616E2076617365");
                decryptTest.run("793ECD59F846615E", "0E329232EA6D0D73133457799BBCDFF1", "6C696E650D0A0000");

                decryptTest.run("25392EDEC93C1CEE", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "8787878787878787");
                decryptTest.run("8A1FEBF13B930592", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "0123456789ABCDEF");
                decryptTest.run("7DD6F8EFF5CA974C", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "596F7572206C6970");
                decryptTest.run("DACD338E796C37BA", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "732061726520736D");
                decryptTest.run("FB291B4A11CE2A70", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "6F6F746865722074");
                decryptTest.run("D5F544CD4BA6068C", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "68616E2076617365");
                decryptTest.run("793ECD59F846615E", "0E329232EA6D0D73133457799BBCDFF10E329232EA6D0D73", "6C696E650D0A0000");

                decryptTest.run("0000000000000000", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "8787878787878787");
                decryptTest.run("31AA59FEB64386A6", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "0123456789ABCDEF");
                decryptTest.run("C0999FDDE378D7ED", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "596F7572206C6970");
                decryptTest.run("727DA00BCA5A84EE", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "732061726520736D");
                decryptTest.run("47F269A4D6438190", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "6F6F746865722074");
                decryptTest.run("D9D52F78F5358499", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "68616E2076617365");
                decryptTest.run("828AC9B453E0E653", "0E329232EA6D0D73133457799BBCDFF1133457799BBCDFF1", "6C696E650D0A0000");
            });
        });
    }
}
