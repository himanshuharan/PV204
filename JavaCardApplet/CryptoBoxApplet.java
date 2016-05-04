/*
 * PACKAGEID: 43727970746f626f78
 * APPLETID: 43727970746f626f78504b47
 */
package applets;

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 *
 * @author rajesh
 */
public class CryptoBoxApplet extends javacard.framework.Applet
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
    //functions added for pv204
    final static byte INS_KEYSETUP                   = (byte) 0x60;
    final static byte INS_REQUESTENCKEY              = (byte) 0x61;
    final static byte INS_RESETPIN                   = (byte) 0x62;
    final static byte INS_GENERATEANDSETKEY          = (byte) 0x63;

    final static short ARRAY_LENGTH                   = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH               = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;
    
    private static final byte password[] = {(byte) 0xED, (byte) 0x9C, (byte) 0xB3, (byte) 0x16, (byte) 0x00,
            (byte) 0x66, (byte) 0x72, (byte) 0xBA, (byte) 0x79, (byte) 0x6C, (byte) 0x84, (byte) 0x59, (byte) 0xB6, (byte) 0xB5,
            (byte) 0x0A, (byte) 0x88, (byte) 0x21, (byte) 0x6B, (byte) 0x84, (byte) 0x7F, (byte) 0x51, (byte) 0xC2, (byte) 0xA4,
            (byte) 0xFF, (byte) 0x16, (byte) 0x23, (byte) 0x2C, (byte) 0x8D, (byte) 0x8C, (byte) 0xDB, (byte) 0xCA, (byte) 0x00};
            

    private   AESKey         m_aesKey = null;
    private   AESKey         m_aesKey_mac = null;   //added for pv204
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;
    private   Cipher         m_encryptCipher_mac = null; //Added for pv204
    private   RandomData     m_secureRandom = null;
    private   MessageDigest  m_hash = null;
    private   OwnerPIN       m_pin = null;
    private   Signature      m_sign = null;
    private   KeyPair        m_keyPair = null;
    private   Key            m_privateKey = null;
    private   Key            m_publicKey = null;
    private   byte           tag[] = null;   //stores mac 
    private   byte           userPIN[] = null;
    //cryptobox parameters
    private   byte      r1[] = new byte[20];    //store random1
    private   byte      r2[] = new byte[20];    //store random2
    private   byte      rp[] = new byte[16];    //store nonce
    private   byte      MK[] = new byte[32];    //store MK (MAC Key)
    private   byte      SK[] = new byte[32];    //store SK (Session Key)
    private   byte      receivedMAC[] = new byte[16];    //store received mac_tag
    private   byte      calculatedMAC[] = new byte[16];  //store received mac_tag   
    private   byte      rc[] = new byte[16];    //store nonce
    //private   byte      password[] = new byte[32];   //store KEY

    private   short          m_apduLogOffset = (short) 0;
    // TEMPORARRY ARRAY IN RAM
    private   byte        m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte       m_dataArray[] = null;

    /**
     * Default constructor
     * Only this class's install method should create the applet object.
     */
    
    protected CryptoBoxApplet(byte[] buffer, short offset, byte length)
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
            //initialize tag of mac
            tag = new byte[16];
            Util.arrayFillNonAtomic(tag, (short) 0, (short) 16, (byte) 0);
            //initialize userPIN
            userPIN = new byte[4];    //store random1
            Util.arrayFillNonAtomic(userPIN, (short) 0, (short) 4, (byte) 0);
            
            //initiliaze cryptobox parameters    
            Util.arrayFillNonAtomic(r1, (short) 0, (short) 20, (byte) 0);
            Util.arrayFillNonAtomic(r2, (short) 0, (short) 20, (byte) 0);
            Util.arrayFillNonAtomic(rp, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(MK, (short) 0, (short) 32, (byte) 0);
            Util.arrayFillNonAtomic(SK, (short) 0, (short) 32, (byte) 0);
            Util.arrayFillNonAtomic(receivedMAC, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(calculatedMAC, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(rc, (short) 0, (short) 16, (byte) 0);
            //Util.arrayFillNonAtomic(password, (short) 0, (short) 32, (byte) 0);
      
            //set password as random key
            //m_secureRandom.generateData(password, (short) 0, (short)16);
            
            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            //added for pv204
            m_aesKey_mac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            //added for Pv204
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
            //added for pv204
            m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);

            m_pin = new OwnerPIN((byte) 5, (byte) 4); //try limit and pin size
            m_pin.update(m_dataArray, (byte) 0, (byte) 4);

            // CREATE RSA KEYS AND PAIR
            m_keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
            
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
        new CryptoBoxApplet (bArray, bOffset, bLength);
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
                case INS_ENCRYPT: Encrypt(apdu); break;
                case INS_DECRYPT: Decrypt(apdu); break;
                case INS_HASH: Hash(apdu); break;
                case INS_RANDOM: Random(apdu); break;
                case INS_VERIFYPIN: VerifyPIN(apdu); break;
                case INS_SETPIN: SetPIN(apdu); break;
                case INS_RETURNDATA: ReturnData(apdu); break;
                case INS_SIGNDATA: Sign(apdu); break;
                case INS_GETAPDUBUFF: GetAPDUBuff(apdu); break;
                case INS_GENERATEANDSETKEY: GenerateAndSetKey(apdu); break;
                case INS_KEYSETUP: KeySetup(apdu); break;
                case INS_REQUESTENCKEY: RequestEncKey(apdu); break;
                case INS_RESETPIN: ResetPIN(apdu); break;
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
    //added for pv204
    void SetMACKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // CHECK EXPECTED LENGTH
      if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      // SET KEY VALUE
      m_aesKey_mac.setKey(apdubuf, ISO7816.OFFSET_CDATA);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
      //m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
    }
    
    // ENCRYPT INCOMING BUFFER
     void Encrypt(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 8) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_encryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }
     
     // ENCRYPT INCOMING BUFFER
     //added for pv204
   void ComputeMAC(byte [] buff) {
      //byte[]    apdubuf = apdu.getBuffer();
      //short     dataLen = apdu.setIncomingAndReceive();
      short dataLen = (short) buff.length;
     
      //short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      //m_encryptCipher_mac.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
      m_encryptCipher_mac.doFinal(buff, (short) 0, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, tag, (short) 0, dataLen);

      // SEND OUTGOING BUFFER
      //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
      
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

    // VERIFY PIN
     void VerifyPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // VERIFY PIN
      if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false)
      ISOException.throwIt(SW_BAD_PIN);
    }

     // SET PIN
     void SetPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // SET NEW PIN
      m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
      Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, userPIN, (short) 0, (short) 4);
      
      //System.out.println("PIN setup completed"); //for testing --to be removed
    }

     void ReturnData(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // RETURN INPU DATA UNCHANGED
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    void Sign(APDU apdu) {
     byte[]    apdubuf = apdu.getBuffer();
     short     dataLen = apdu.setIncomingAndReceive();
     short     signLen = 0;


     // STARTS KEY GENERATION PROCESS
     m_keyPair.genKeyPair();

     // OBTAIN KEY REFERENCES
     m_publicKey = m_keyPair.getPublic();
     m_privateKey = m_keyPair.getPrivate();

     // CREATE SIGNATURE OBJECT
     //Signature m_sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

     // INIT WITH PRIVATE KEY
     m_sign.init(m_privateKey, Signature.MODE_SIGN);

     // SIGN INCOMING BUFFER
     signLen = m_sign.sign(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen, m_ramArray, (byte) 0);

     // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
     Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, signLen);

     // SEND OUTGOING BUFFER
     apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signLen);
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
   
   ////////////////////////Rajesh Pal's Function///////////////////////

// GENERATE RANDOM KEY AND SET ENCRYPTION & DECRYPTION KEY FOR AES
    void GenerateAndSetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // CHECK EXPECTED LENGTH
      if ((short) (apdubuf[ISO7816.OFFSET_P1] * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      // GENERATE DATA
      m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);

      // SET KEY VALUE
      m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
      
      //The secret key is not returned back to the host application; enable following line for testing
      //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
    }
    
    //key setup function
     void KeySetup(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      /*** Step1: check integrity of packet ***/
      
      //get R1 (=PIN||r1)
      Util.arrayCopyNonAtomic(userPIN, (short) 0, r1, (short) 0, (short) 4);
      Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, r1, (short) 4, (short) 16);
      //System.out.println("R1: " + bytesToHex(r1));
      
      //get R2 (=PIN||r2)
      Util.arrayCopyNonAtomic(userPIN, (short) 0, r2, (short) 0, (short) 4);
      Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + 16), r2, (short) 4, (short) 16);
      //System.out.println("R2: " + bytesToHex(r2));
      
      //get Rp (encrypted)
      Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + 32), rp, (short) 0, (short) 16);
      //System.out.println("Rp: " + bytesToHex(rp));
      
      //get MAC
      Util.arrayCopyNonAtomic(apdubuf, (short)(64), receivedMAC, (short) 0, (short) 16);
      //System.out.println("receivedMAC: " + bytesToHex(receivedMAC));
      
      //compute SK (=SHA256(PIN||r1))
      if (m_hash != null) {
          m_hash.doFinal(r1, (short) 0, (short) 20, m_ramArray, (short) 0);
      }
      else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);

      // Copy SK
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, SK, (short) 0, m_hash.getLength());
      //System.out.println("SK: " + bytesToHex(SK));

      //prepare MAC key (MK)
      if (m_hash != null) {
          m_hash.doFinal(r2, (short) 0, (short) 20, m_ramArray, (short) 0);
      }
      else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);

      // COPY calculated mac
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, MK, (short) 0, m_hash.getLength());
      //System.out.println("MK: " + bytesToHex(MK));

      //compute calculated_MAC
      m_aesKey_mac.setKey(MK, (short) 0);
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
      m_encryptCipher_mac.doFinal(apdubuf, (short) 0, (short) 64, m_ramArray, (short) 0);
      Util.arrayCopyNonAtomic(m_ramArray, (short) 48, calculatedMAC, (short) 0, (short) 16);
      //System.out.println("calculatedMAC: " + bytesToHex(calculatedMAC));
      
      //check if receivedMAC and calculatedMAC matches
      byte compareResult = Util.arrayCompare(receivedMAC, (short) 0, calculatedMAC, (short) 0, (short) 16);
      if(compareResult != 0) { //System.out.println("Error: MAC unmatched"); 
      ISOException.throwIt(SW_KEY_LENGTH_BAD);}
      
      //decrypt and get RP
      m_aesKey.setKey(SK, (short) 0);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
      m_decryptCipher.doFinal(apdubuf, (short) 37, (short) 16, m_ramArray, (short) 0);
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, rp, (short) 0, (short) 16);
      //System.out.println("decrypted_Rp: " + bytesToHex(rp));
      
      /*prepare response APDU (copy rp, rc, mac)*/
      //pack rp
      short lastByteRp = rp[15];
      rp[15] = (byte) (lastByteRp + 1);
      Util.arrayCopyNonAtomic(rp, (short) 0, m_ramArray, (short) 0, (short) 16);
      //generate rc and pack
      m_secureRandom.generateData(rc, (short) 0, (short) 16);
      Util.arrayCopyNonAtomic(rc, (short) 0, m_ramArray, (short) 16, (short) 16);
      //System.out.println("Rc_setKey: " + bytesToHex(rc));
      //encrypt packet
      m_aesKey.setKey(SK, (short) 0);
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      //System.out.println("beforeEnc: " + bytesToHex(m_ramArray));
      m_encryptCipher.doFinal(m_ramArray, (short) 0, (short) 32, apdubuf, (short) 0);
      //System.out.println("afterEnc: " + bytesToHex(apdubuf));
      //calculate and pack MAC
      m_encryptCipher_mac.doFinal(apdubuf, (short) 0, (short) 32, m_ramArray, (short) 0);
      //System.out.println("afterMAC: " + bytesToHex(m_ramArray));
      Util.arrayCopyNonAtomic(m_ramArray, (short) 16, apdubuf, (short) (32), (short) 16);
      //System.out.println("responseAPDC: " + bytesToHex(apdubuf));
      
      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend((short) 0, (short) 48);
      
      //prepare expected rp, rc
      lastByteRp = rp[15];
      rp[15] = (byte) (lastByteRp + 1);
      short lastByteRc = rc[15];
      rc[15] = (byte) (lastByteRc + 1);
      
    }
     
     
     
     
     ///////////////////////////////////////////////////////////////////////////
     void RequestEncKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      /*** Step1: check integrity of packet ***/
      //take out received MAC
      Util.arrayCopyNonAtomic(apdubuf, (short)(48), receivedMAC, (short) 0, (short) 16);
      //System.out.println("receivedMAC_requestEncKey: " + bytesToHex(receivedMAC));
      
      //compute calculated_MAC
      m_aesKey_mac.setKey(MK, (short) 0);
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
      m_encryptCipher_mac.doFinal(apdubuf, (short) 0, (short) 48, m_ramArray, (short) 0);
      Util.arrayCopyNonAtomic(m_ramArray, (short) 32, calculatedMAC, (short) 0, (short) 16);
      //System.out.println("calculatedMAC_requestEncKe: " + bytesToHex(calculatedMAC));
      
      //check if receivedMAC and calculatedMAC matches, then accept packet
      byte compareResult = Util.arrayCompare(receivedMAC, (short) 0, calculatedMAC, (short) 0, (short) 16);
      if(compareResult != 0) { //System.out.println("Error: MAC unmatched"); 
      ISOException.throwIt(SW_KEY_LENGTH_BAD);}
      //else System.out.println("MAC matched");
      
      /*** Step2: check freshness ***/
      byte rp_rcvd[] = new byte[16];    //rp_rcvd == rp (already incremented in prev step)
      byte rc_rcvd[] = new byte[16];    //rc_rcvd == rc (already incremented in prev step)
      Util.arrayFillNonAtomic(rp_rcvd, (short) 0, (short) 16, (byte) 0);
      Util.arrayFillNonAtomic(rc_rcvd, (short) 0, (short) 16, (byte) 0);
      m_aesKey.setKey(SK, (short) 0);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
      m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, (short) 32, m_ramArray, (short) 0);
      
      //get rp_rcvd (encrypted)
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, rp_rcvd, (short) 0, (short) 16);
      //System.out.println("Rp_rcvd: " + bytesToHex(rp_rcvd));
      
      //get rc_rcvd (encrypted)
      Util.arrayCopyNonAtomic(m_ramArray, (short)(16), rc_rcvd, (short) 0, (short) 16);
      //System.out.println("Rc_rcvd: " + bytesToHex(rc_rcvd));
      
      //System.out.println("Rc_requestEncKey: " + bytesToHex(rc));
      //check if rp_rcvd==rp and rc_rcvd==rc
      byte ret = Util.arrayCompare(rp_rcvd, (short) 0, rp, (short) 0, (short) 16);
      if(ret != 0) { 
          //System.out.println("Error: Rp unmatched"); 
          ISOException.throwIt(SW_KEY_LENGTH_BAD);}
      else {
          byte ret1 = Util.arrayCompare(rc_rcvd, (short) 0, rc, (short) 0, (short) 16);
          if(ret1 != 0) { 
              //System.out.println("Error: Rc unmatched");
              ISOException.throwIt(SW_KEY_LENGTH_BAD);}
          //else {
          //    System.out.println("Freshness checked, found OK.");
          //}
       }
          
       /*** Step3: Provide KEY (in encrypted form) ***/ 
       //prepare response APDU (copy KEY, rp+2, rc+1, mac)
       Util.arrayCopyNonAtomic(password, (short) 0, m_ramArray, (short) 0, (short) 32);
       //increment and copy rp
      short lastByteRp = rp[15];
      rp[15] = (byte) (lastByteRp + 1);
      Util.arrayCopyNonAtomic(rp, (short) 0, m_ramArray, (short) 32, (short) 16);
      //copy rc
      short lastByteRc = rc[15];
      rc[15] = (byte) (lastByteRc + 1);
      Util.arrayCopyNonAtomic(rc, (short) 0, m_ramArray, (short) 48, (short) 16);
      //encrypt data(key+rp_3+rc_2)
      m_aesKey.setKey(SK, (short) 0);
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_encryptCipher.doFinal(m_ramArray, (short) 0, (short) 64, apdubuf, (short) 0);
      //System.out.println("afterEnc: " + bytesToHex(apdubuf));
      //calculate and pack MAC
      m_encryptCipher_mac.doFinal(apdubuf, (short) 0, (short) 64, m_ramArray, (short) 0);
      //System.out.println("afterMAC: " + bytesToHex(m_ramArray));
      Util.arrayCopyNonAtomic(m_ramArray, (short) 48, apdubuf, (short) (64), (short) 16);
      //System.out.println("responseAPDC: " + bytesToHex(apdubuf));
      
      
      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend((short) 0, (short) 80);
      
      //prepare expected rp, rc
      lastByteRp = rp[15];
      rp[15] = (byte) (lastByteRp + 1);
      lastByteRc = rc[15];
      rc[15] = (byte) (lastByteRc + 1);
      //close secure channel
      Util.arrayFillNonAtomic(MK, (short) 0, (short) 32, (byte) 0);
      Util.arrayFillNonAtomic(SK, (short) 0, (short) 32, (byte) 0);
    
     }
     
     
     
     
     
     
     
     ///////////////////////////////////////////////////////////////////////////
     
     void ResetPIN(APDU apdu){
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      /*** Step1: check integrity of packet ***/
      //take out received MAC
      Util.arrayCopyNonAtomic(apdubuf, (short)(64), receivedMAC, (short) 0, (short) 16);
      //System.out.println("receivedMAC_requestEncKey: " + bytesToHex(receivedMAC));
      
      //compute calculated_MAC
      m_aesKey_mac.setKey(MK, (short) 0);
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
      m_encryptCipher_mac.doFinal(apdubuf, (short) 0, (short) 64, m_ramArray, (short) 0);
      Util.arrayCopyNonAtomic(m_ramArray, (short) 48, calculatedMAC, (short) 0, (short) 16);
      //System.out.println("calculatedMAC_requestEncKe: " + bytesToHex(calculatedMAC));
      
      //check if receivedMAC and calculatedMAC matches, then accept packet
      byte compareResult = Util.arrayCompare(receivedMAC, (short) 0, calculatedMAC, (short) 0, (short) 16);
      if(compareResult != 0) { 
          //System.out.println("Error: MAC unmatched"); 
          ISOException.throwIt(SW_KEY_LENGTH_BAD);}
      //else System.out.println("MAC matched");
      
      /*** Step2: check freshness ***/
      byte rp_rcvd[] = new byte[16];    //rp_rcvd == rp (already incremented in prev step)
      byte rc_rcvd[] = new byte[16];    //rc_rcvd == rc (already incremented in prev step)
      Util.arrayFillNonAtomic(rp_rcvd, (short) 0, (short) 16, (byte) 0);
      Util.arrayFillNonAtomic(rc_rcvd, (short) 0, (short) 16, (byte) 0);
      m_aesKey.setKey(SK, (short) 0);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
      m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, (short) 48, m_ramArray, (short) 0);
      
      //get rp_rcvd (encrypted)
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, rp_rcvd, (short) 0, (short) 16);
      //System.out.println("Rp_rcvd: " + bytesToHex(rp_rcvd));
      
      //get rc_rcvd (encrypted)
      Util.arrayCopyNonAtomic(m_ramArray, (short)(16), rc_rcvd, (short) 0, (short) 16);
      //System.out.println("Rc_rcvd: " + bytesToHex(rc_rcvd));
      
      
      //check if rp_rcvd==rp and rc_rcvd==rc
      byte ret = Util.arrayCompare(rp_rcvd, (short) 0, rp, (short) 0, (short) 16);
      if(ret != 0) { //System.out.println("Error: Rp unmatched"); 
          ISOException.throwIt(SW_KEY_LENGTH_BAD);}
      else {
          byte ret1 = Util.arrayCompare(rc_rcvd, (short) 0, rc, (short) 0, (short) 16);
          if(ret1 != 0) { //System.out.println("Error: Rc unmatched"); 
              ISOException.throwIt(SW_KEY_LENGTH_BAD);}
          //else {
          //    System.out.println("Freshness checked, found OK.");
          //}
       }
      
      //get new PIN
      Util.arrayCopyNonAtomic(m_ramArray, (short)(37), userPIN, (short) 0, (short) 4);
      m_pin.update(userPIN, (short)(0), (byte) 4);
      //System.out.println("user new PIN: " + userPIN);
          
       /*** Step3: Provide Acknowledgment ***/
       //increment and copy rp
      short lastByteRp = rp[15];
      rp[15] = (byte) (lastByteRp + 1);
      Util.arrayCopyNonAtomic(rp, (short) 0, m_ramArray, (short) 0, (short) 16);
      //copy rc
      short lastByteRc = rc[15];
      rc[15] = (byte) (lastByteRc + 1);
      Util.arrayCopyNonAtomic(rc, (short) 0, m_ramArray, (short) 16, (short) 16);
      //encrypt data(apdu_header+rp_2+rc_1)
      m_aesKey.setKey(SK, (short) 0);
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_encryptCipher.doFinal(m_ramArray, (short) 0, (short) 32, apdubuf, (short) 0);
      //calculate and pack MAC
      m_encryptCipher_mac.doFinal(apdubuf, (short) 0, (short) 32, m_ramArray, (short) 0);
      //System.out.println("afterMAC: " + bytesToHex(m_ramArray));
      Util.arrayCopyNonAtomic(m_ramArray, (short) 16, apdubuf, (short) (32), (short) 16);
      
      
      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend((short) 0, (short) 48);
      
      //prepare expected rp, rc
      lastByteRp = rp[15];
      rp[15] = (byte) (lastByteRp + 1);
      lastByteRc = rc[15];
      rc[15] = (byte) (lastByteRc + 1);
      //close secure channel
      Util.arrayFillNonAtomic(MK, (short) 0, (short) 32, (byte) 0);
      Util.arrayFillNonAtomic(SK, (short) 0, (short) 32, (byte) 0);
    
     }
    
}
