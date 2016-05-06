/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package applets;

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import javacard.security.KeyBuilder;


public class SimpleApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ENCRYPT                    = (byte) 0x50;
    final static byte INS_DECRYPT                    = (byte) 0x51;
    final static byte INS_SETKEY                     = (byte) 0x52;
    final static byte INS_HASH                       = (byte) 0x53;
    final static byte INS_RANDOM                     = (byte) 0x54;
    final static byte INS_VERIFYPIN                  = (byte) 0x55;
    final static byte INS_SETPIN                     = (byte) 0x56;
    final static byte INS_RETURNDATA                 = (byte) 0x57;
    final static byte INS_SIGNDATA                   = (byte) 0x58;
    final static byte INS_GETAPDUBUFF                = (byte) 0x59;
    final static byte INS_SETKEY_MAC                 = (byte) 0x5a;
    final static byte INS_MAC                        = (byte) 0x5b;
    final static byte INS_LOAD_RSA_PUBLIC_KEY        = (byte) 0x5c;
    final static byte INS_ENCRYPT_RSA                = (byte) 0x5d;
    
    final static short ARRAY_LENGTH                   = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH               = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;

    private   AESKey         m_aesKey = null;
    private   AESKey         m_aesKey_mac = null;
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;
    private   Cipher         m_encryptCipher_mac = null;
    private   RandomData     m_secureRandom = null;
    private   MessageDigest  m_hash = null;
    private   OwnerPIN       m_pin = null;
    private   Signature      m_sign = null;
    private   KeyPair        m_keyPair = null;
    private   Key            m_privateKey = null;
    private   Key            m_publicKey = null;
   
    private   short               m_apduLogOffset = (short) 0;
    // TEMPORARRY ARRAY IN RAM
    private   byte                m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte                m_dataArray[] = null;
    private   static Cipher       rsaCipher = null;
    private   static RSAPublicKey pubkey = null;

    /**
     * LabakApplet default constructor
     * Only this class's install method should create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // // checks wrong data length
           // if(buffer[dataOffset] !=  <PUT YOUR PARAMETERS LENGTH> )
           //     // return received proprietary data length in the reason
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + offset + length - dataOffset));

            // go to proprietary data
            dataOffset++;

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            m_aesKey_mac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_encryptCipher_mac = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

            // CREATE RANDOM DATA GENERATORS
             m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);
            m_aesKey_mac.setKey(m_dataArray, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
            m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);

            m_pin = new OwnerPIN((byte) 5, (byte) 4);
            m_pin.update(m_dataArray, (byte) 0, (byte) 4);

            // CREATE RSA KEYS AND PAIR
            m_keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
            rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);    
           
            // INIT HASH ENGINE
            try {
                m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            }
            catch (CryptoException e) {
               // HASH ENGINE NOT AVAILABLE
            }

            // update flag
            isOP2 = true;

        } else {
           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // if(length != <PUT YOUR PARAMETERS LENGTH> )
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
       }

        // <PUT YOUR CREATION ACTION HERE>

        // register this instance
          register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new SimpleApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>

        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        //short dataLen = apdu.setIncomingAndReceive();
        //Util.arrayCopyNonAtomic(apduBuffer, (short) 0, m_dataArray, m_apduLogOffset, (short) (5 + dataLen));
        //m_apduLogOffset = (short) (m_apduLogOffset + 5 + dataLen);

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_SETKEY: SetKey(apdu); break;
                case INS_SETKEY_MAC: SetMACKey(apdu); break;
                case INS_MAC: computeMAC(apdu); break;
                case INS_ENCRYPT: Encrypt(apdu); break;
                case INS_DECRYPT: Decrypt(apdu); break;
                case INS_HASH: Hash(apdu); break;
                case INS_RANDOM: Random(apdu); break;
                case INS_RETURNDATA: ReturnData(apdu); break;
                case INS_GETAPDUBUFF: GetAPDUBuff(apdu); break;
                case INS_LOAD_RSA_PUBLIC_KEY: loadJavacardPublicKey(apdu) ; break;
                case INS_ENCRYPT_RSA: rsaEncryption(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;
            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // CHECK EXPECTED LENGTH
      if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      // SET KEY VALUE
      m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
    }

    // SET ENCRYPTION & DECRYPTION KEY
    void SetMACKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // CHECK EXPECTED LENGTH
      if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      // SET KEY VALUE
      m_aesKey_mac.setKey(apdubuf, ISO7816.OFFSET_CDATA);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
    }
    

    
    // ENCRYPT INCOMING BUFFER
     void Encrypt(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_encryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // DECRYPT INCOMING BUFFER
    void Decrypt(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 8) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    
    // ENCRYPT INCOMING BUFFER
     void computeMAC(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_encryptCipher_mac.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }    

     
     // HASH INCOMING BUFFER
     void Hash(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      if (m_hash != null) {
          m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
      }
      else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());
    }

    // GENERATE RANDOM DATA
     void Random(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // GENERATE DATA
      m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
    }



     void ReturnData(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // RETURN INPU DATA UNCHANGED
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }


   void GetAPDUBuff(APDU apdu) {
    byte[]    apdubuf = apdu.getBuffer();

    // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
    Util.arrayCopyNonAtomic(m_dataArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_apduLogOffset);
    short tempLength = m_apduLogOffset;
    m_apduLogOffset = 0;
    // SEND OUTGOING BUFFER
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, tempLength);
  }

   
    public static void loadJavacardPublicKey( APDU apdu ){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        byte         modulus[] = new byte[129];
        byte         exponent[] = new byte[3];

        int i,k=0;
        short modlen = 128, explen = 3;

        modulus[0]= (byte) 0; //SET the MSB of Modulus to 0
        for( i=10 ; i<137 ; i++){
            modulus[k]=apdubuf[i+ISO7816.OFFSET_CDATA];
            k++;  
        }
        
        modulus[k]=apdubuf[137];
        for(i=140;i<143;i++) {
            exponent[i-140]=apdubuf[i+ISO7816.OFFSET_CDATA];
        }        
        pubkey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);
        pubkey.setExponent(exponent, (short) 0, explen);
        pubkey.setModulus(modulus,(short) 0, modlen); 
        rsaCipher.init(pubkey, Cipher.MODE_ENCRYPT);    
    }

    public static void rsaEncryption(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        short     ctLen;

        ctLen = rsaCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, apdubuf, (short) 0);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, ctLen);        
    }
   
}

