

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using emv_tag_index_t = System.Byte;
using emv_tag_t = System.Int32;

namespace uFr
{
    
    using DL_STATUS = System.UInt32;

    public enum UFR_STATUS
    {
        UFR_OK = 0x00,
        UFR_COMMUNICATION_ERROR = 0x01,
        UFR_CHKSUM_ERROR = 0x02,
        UFR_READING_ERROR = 0x03,
        UFR_WRITING_ERROR = 0x04,
        UFR_BUFFER_OVERFLOW = 0x05,
        UFR_MAX_ADDRESS_EXCEEDED = 0x06,
        UFR_MAX_KEY_INDEX_EXCEEDED = 0x07,
        UFR_NO_CARD = 0x08,
        UFR_COMMAND_NOT_SUPPORTED = 0x09,
        UFR_FORBIDEN_DIRECT_WRITE_IN_SECTOR_TRAILER = 0x0A,
        UFR_ADDRESSED_BLOCK_IS_NOT_SECTOR_TRAILER = 0x0B,
        UFR_WRONG_ADDRESS_MODE = 0x0C,
        UFR_WRONG_ACCESS_BITS_VALUES = 0x0D,
        UFR_AUTH_ERROR = 0x0E,
        UFR_PARAMETERS_ERROR = 0x0F,
        UFR_MAX_SIZE_EXCEEDED = 0x10,
        UFR_UNSUPPORTED_CARD_TYPE = 0x11,

        UFR_COMMUNICATION_BREAK = 0x50,
        UFR_NO_MEMORY_ERROR = 0x51,
        UFR_CAN_NOT_OPEN_READER = 0x52,
        UFR_READER_NOT_SUPPORTED = 0x53,
        UFR_READER_OPENING_ERROR = 0x54,
        UFR_READER_PORT_NOT_OPENED = 0x55,
        UFR_CANT_CLOSE_READER_PORT = 0x56,

        UFR_WRITE_VERIFICATION_ERROR = 0x70,
        UFR_BUFFER_SIZE_EXCEEDED = 0x71,
        UFR_VALUE_BLOCK_INVALID = 0x72,
        UFR_VALUE_BLOCK_ADDR_INVALID = 0x73,
        UFR_VALUE_BLOCK_MANIPULATION_ERROR = 0x74,
        UFR_WRONG_UI_MODE = 0x75,
        UFR_KEYS_LOCKED = 0x76,
        UFR_KEYS_UNLOCKED = 0x77,
        UFR_WRONG_PASSWORD = 0x78,
        UFR_CAN_NOT_LOCK_DEVICE = 0x79,
        UFR_CAN_NOT_UNLOCK_DEVICE = 0x7A,
        UFR_DEVICE_EEPROM_BUSY = 0x7B,
        UFR_RTC_SET_ERROR = 0x7C,

        ANTI_COLLISION_DISABLED = 0x7D,
        NO_TAGS_ENUMERRATED = 0x7E,
        CARD_ALREADY_SELECTED = 0x7F,

        // NDEF error codes
        UFR_WRONG_NDEF_CARD_FORMAT = 0x80,
        UFR_NDEF_MESSAGE_NOT_FOUND = 0x81,
        UFR_NDEF_UNSUPPORTED_CARD_TYPE = 0x82,
        UFR_NDEF_CARD_FORMAT_ERROR = 0x83,
        UFR_MAD_NOT_ENABLED = 0x84,
        UFR_MAD_VERSION_NOT_SUPPORTED = 0x85,
        UFR_NDEF_MESSAGE_NOT_COMPATIBLE = 0x86,

        // Tag emulation mode errors:
        FORBIDDEN_IN_TAG_EMULATION_MODE = 0x90,

        // FTDI errors:
        UFR_FT_STATUS_ERROR_1 = 0xA0,
        UFR_FT_STATUS_ERROR_2 = 0xA1,
        UFR_FT_STATUS_ERROR_3 = 0xA2,
        UFR_FT_STATUS_ERROR_4 = 0xA3,
        UFR_FT_STATUS_ERROR_5 = 0xA4,
        UFR_FT_STATUS_ERROR_6 = 0xA5,
        UFR_FT_STATUS_ERROR_7 = 0xA6,
        UFR_FT_STATUS_ERROR_8 = 0xA7,
        UFR_FT_STATUS_ERROR_9 = 0xA8,

        //MIFARE PLUS error codes
        UFR_MFP_COMMAND_OVERFLOW = 0xB0,
        UFR_MFP_INVALID_MAC = 0xB1,
        UFR_MFP_INVALID_BLOCK_NR = 0xB2,
        UFR_MFP_NOT_EXIST_BLOCK_NR = 0xB3,
        UFR_MFP_COND_OF_USE_ERROR = 0xB4,
        UFR_MFP_LENGTH_ERROR = 0xB5,
        UFR_MFP_GENERAL_MANIP_ERROR = 0xB6,
        UFR_MFP_SWITCH_TO_ISO14443_4_ERROR = 0xB7,
        UFR_MFP_ILLEGAL_STATUS_CODE = 0xB8,
        UFR_MFP_MULTI_BLOCKS_READ = 0xB9,

        //NT4H error codes
        NT4H_COMMAND_ABORTED = 0xC0,
        NT4H_LENGTH_ERROR = 0xC1,
        NT4H_PARAMETER_ERROR = 0xC2,
        NT4H_NO_SUCH_KEY = 0xC3,
        NT4H_PERMISSION_DENIED = 0xC4,
        NT4H_AUTHENTICATION_DELAY = 0xC5,
        NT4H_MEMORY_ERROR = 0xC6,
        NT4H_INTEGRITY_ERROR = 0xC7,
        NT4H_FILE_NOT_FOUND = 0xC8,
        NT4H_BOUNDARY_ERROR = 0xC9,
        NT4H_INVALID_MAC = 0xCA,
        NT4H_NO_CHANGES = 0xCB,

        // multiple units - return from the functions with ReaderList_ prefix in name
        UFR_DEVICE_WRONG_HANDLE = 0x100,
        UFR_DEVICE_INDEX_OUT_OF_BOUND,
        UFR_DEVICE_ALREADY_OPENED,
        UFR_DEVICE_ALREADY_CLOSED,
        UFR_DEVICE_IS_NOT_CONNECTED,

        // Originality Check Error Codes:
        UFR_NOT_NXP_GENUINE = 0x200,
        UFR_OPEN_SSL_DYNAMIC_LIB_FAILED,
        UFR_OPEN_SSL_DYNAMIC_LIB_NOT_FOUND,

        // DESFIRE Card Status Error Codes:
        READER_ERROR = 0xBB7,                   // 2999 [dec]
        NO_CARD_DETECTED = 0xBB8,               // 3000 [dec]
        CARD_OPERATION_OK = 0xBB9,              // 3001 [dec]
        WRONG_KEY_TYPE = 0xBBA,                 // 3002 [dec]
        KEY_AUTH_ERROR = 0xBBB,                 // 3003 [dec]
        CARD_CRYPTO_ERROR = 0xBBC,              // 3004 [dec]
        READER_CARD_COMM_ERROR = 0xBBD,         // 3005 [dec]
        PC_READER_COMM_ERROR = 0xBBE,           // 3006 [dec]
        COMMIT_TRANSACTION_NO_REPLY = 0xBBF,    // 3007 [dec]
        COMMIT_TRANSACTION_ERROR = 0xBC0,       // 3008 [dec]
        NOT_SUPPORTED_KEY_TYPE = 0xBC2,         // 3010 [dec]

        DESFIRE_CARD_NO_CHANGES = 0x0C0C,
        DESFIRE_CARD_OUT_OF_EEPROM_ERROR = 0x0C0E,
        DESFIRE_CARD_ILLEGAL_COMMAND_CODE = 0x0C1C,
        DESFIRE_CARD_INTEGRITY_ERROR = 0x0C1E,
        DESFIRE_CARD_NO_SUCH_KEY = 0x0C40,
        DESFIRE_CARD_LENGTH_ERROR = 0x0C7E,
        DESFIRE_CARD_PERMISSION_DENIED = 0x0C9D,
        DESFIRE_CARD_PARAMETER_ERROR = 0x0C9E,
        DESFIRE_CARD_APPLICATION_NOT_FOUND = 0x0CA0,
        DESFIRE_CARD_APPL_INTEGRITY_ERROR = 0x0CA1,
        DESFIRE_CARD_AUTHENTICATION_ERROR = 0x0CAE,
        DESFIRE_CARD_ADDITIONAL_FRAME = 0x0CAF,
        DESFIRE_CARD_BOUNDARY_ERROR = 0x0CBE,
        DESFIRE_CARD_PICC_INTEGRITY_ERROR = 0x0CC1,
        DESFIRE_CARD_COMMAND_ABORTED = 0x0CCA,
        DESFIRE_CARD_PICC_DISABLED_ERROR = 0x0CCD,
        DESFIRE_CARD_COUNT_ERROR = 0x0CCE,
        DESFIRE_CARD_DUPLICATE_ERROR = 0x0CDE,
        DESFIRE_CARD_EEPROM_ERROR_DES = 0x0CEE,
        DESFIRE_CARD_FILE_NOT_FOUND = 0x0CF0,
        DESFIRE_CARD_FILE_INTEGRITY_ERROR = 0x0CF1,
        DESFIRE_CATD_AUTHENTICATION_DELAY = 0X0CAD,

        // uFCoder library errors:
        UFR_NOT_IMPLEMENTED = 0x1000,
        UFR_COMMAND_FAILED = 0x1001,
        UFR_TIMEOUT_ERR = 0x1002,
        UFR_FILE_SYSTEM_ERROR = 0x1003,
        UFR_FILE_SYSTEM_PATH_NOT_EXISTS = 0x1004,
        UFR_FILE_NOT_EXISTS = 0x1005,

        //SAM module error codes:
        UFR_SAM_APDU_ERROR = 0x2000,
        UFR_SAM_AUTH_ERROR,
        UFR_SAM_CRYPTO_ERROR,

        // JC cards APDU Error Codes:
        UFR_APDU_TRANSCEIVE_ERROR = 0xAE,
        UFR_APDU_JC_APP_NOT_SELECTED = 0x6000,
        UFR_APDU_JC_APP_BUFF_EMPTY = 0x6001,
        UFR_APDU_WRONG_SELECT_RESPONSE = 0x6002,
        UFR_APDU_WRONG_KEY_TYPE = 0x6003,
        UFR_APDU_WRONG_KEY_SIZE = 0x6004,
        UFR_APDU_WRONG_KEY_PARAMS = 0x6005,
        UFR_APDU_WRONG_SIGNING_ALGORITHM = 0x6006,
        UFR_APDU_PLAIN_TEXT_MAX_SIZE_EXCEEDED = 0x6007,
        UFR_APDU_UNSUPPORTED_KEY_SIZE = 0x6008,
        UFR_APDU_UNSUPPORTED_ALGORITHMS = 0x6009,
        UFR_APDU_PKI_OBJECT_NOT_FOUND = 0x600A,
        UFR_APDU_MAX_PIN_LENGTH_EXCEEDED = 0x600B,
        UFR_DIGEST_LENGTH_DOES_NOT_MATCH = 0x600C,

        // reserved: 0x6100,
        CRYPTO_SUBSYS_NOT_INITIALIZED = 0x6101,
        CRYPTO_SUBSYS_SIGNATURE_VERIFICATION_ERROR = 0x6102,
        CRYPTO_SUBSYS_MAX_HASH_INPUT_EXCEEDED = 0x6103,
        CRYPTO_SUBSYS_INVALID_HASH_ALGORITHM = 0x6104,
        CRYPTO_SUBSYS_INVALID_CIPHER_ALGORITHM = 0x6105,
        CRYPTO_SUBSYS_INVALID_PADDING_ALGORITHM = 0x6106,
        CRYPTO_SUBSYS_WRONG_SIGNATURE = 0x6107,
        CRYPTO_SUBSYS_WRONG_HASH_OUTPUT_LENGTH = 0x6108,
        CRYPTO_SUBSYS_UNKNOWN_ECC_CURVE = 0x6109,
        CRYPTO_SUBSYS_HASHING_ERROR = 0x610A,
        CRYPTO_SUBSYS_INVALID_SIGNATURE_PARAMS = 0x610B,
        CRYPTO_SUBSYS_INVALID_RSA_PUB_KEY = 0x610C,
        CRYPTO_SUBSYS_INVALID_ECC_PUB_KEY_PARAMS = 0x610D,
        CRYPTO_SUBSYS_INVALID_ECC_PUB_KEY = 0x610E,

        UFR_WRONG_PEM_CERT_FORMAT = 0x61C0,

        // X.509 specific statuses:
        X509_CAN_NOT_OPEN_FILE = 0x6200,
        X509_WRONG_DATA = 0x6201,
        X509_WRONG_LENGTH = 0x6202,
        X509_UNSUPPORTED_PUBLIC_KEY_TYPE = 0x6203,
        X509_UNSUPPORTED_PUBLIC_KEY_SIZE = 0x6204,
        X509_UNSUPPORTED_PUBLIC_KEY_EXPONENT = 0x6205,
        X509_EXTENSION_NOT_FOUND = 0x6206,
        X509_WRONG_SIGNATURE = 0x6207,
        X509_UNKNOWN_PUBLIC_KEY_TYPE = 0x6208,
        X509_WRONG_RSA_PUBLIC_KEY_FORMAT = 0x6209,
        X509_WRONG_ECC_PUBLIC_KEY_FORMAT = 0x620A,
        X509_SIGNATURE_NOT_MATCH_CA_PUBLIC_KEY = 0x620B,
        X509_UNSUPPORTED_SIGNATURE_SCH = 0x620C,
        X509_UNSUPPORTED_ECC_CURVE = 0x620D,

        // PKCS#7 specific statuses:
        PKCS7_WRONG_DATA = 0x6241,
        PKCS7_UNSUPPORTED_SIGNATURE_SCHEME = 0x6242,
        PKCS7_SIG_SCH_NOT_MATCH_CERT_KEY_TYPE = 0x6243,

        PKCS7_WRONG_SIGNATURE = 0x6247,

        // MRTD specific statuses:
        MRTD_SECURE_CHANNEL_SESSION_FAILED = 0x6280,
        MRTD_WRONG_SOD_DATA = 0x6281,
        MRTD_WRONG_SOD_LENGTH = 0x6282,
        MRTD_UNKNOWN_DIGEST_ALGORITHM = 0x6283,
        MRTD_WARNING_DOES_NOT_CONTAINS_DS_CERT = 0x6284,
        MRTD_DATA_GROUOP_INDEX_NOT_EXIST = 0x6285,
        MRTD_EF_COM_WRONG_DATA = 0x6286,
        MRTD_EF_DG_WRONG_DATA = 0x6287,
        MRTD_EF_DG1_WRONG_LDS_VERSION_LENGTH = 0x6288,
        MRTD_VERIFY_CSCA_NOT_EXIST = 0x6289,
        MRTD_VERIFY_WRONG_DS_SIGNATURE = 0x628A,
        MRTD_VERIFY_WRONG_CSCA_SIGNATURE = 0x628B,
        MRTD_MRZ_CHECK_ERROR = 0x628C,

        // ICAO Master List specific statuses:
        ICAO_ML_WRONG_FORMAT = 0x6300,
        ICAO_ML_CAN_NOT_OPEN_FILE = 0x6301,
        ICAO_ML_CAN_NOT_READ_FILE = 0x6302,
        ICAO_ML_CERTIFICATE_NOT_FOUND = 0x6303,
        ICAO_ML_WRONG_SIGNATURE = 0x6307,

        // EMV specific statuses
        SYS_ERR_OUT_OF_MEMORY = 0x7001,
        EMV_ERR_WRONG_INPUT_DATA = 0x7002,
        EMV_ERR_MAX_TAG_LEN_BYTES_EXCEEDED = 0x7004,
        EMV_ERR_TAG_NOT_FOUND = 0x7005,
        EMV_ERR_TAG_WRONG_SIZE = 0x7006,
        EMV_ERR_TAG_WRONG_TYPE = 0x7007,
        EMV_ERR_IN_CARD_READER = 0x7008,
        EMV_ERR_READING_RECORD = 0x7009,
        EMV_ERR_PDOL_IS_EMPTY = 0x7010,
        EMV_ERR_LIST_FORMAT_NOT_FOUND = 0x7011,
        EMV_ERR_AFL_NOT_FOUND = 0x7012,
        EMV_ERR_AID_NOT_FOUND = 0x7013,

        // ISO7816-4 Errors (R-APDU) - 2 SW bytes returned by the card, prefixed with 0x000A:
        UFR_APDU_SW_TAG = 0x000A0000,
        UFR_APDU_SW_OPERATION_IS_FAILED = 0x000A6300,
        UFR_APDU_SW_WRONG_LENGTH = 0x000A6700,
        UFR_APDU_SW_SECURITY_STATUS_NOT_SATISFIED = 0x000A6982,
        UFR_APDU_SW_AUTHENTICATION_METHOD_BLOCKED = 0x000A6983,
        UFR_APDU_SW_DATA_INVALID = 0x000A6984,
        UFR_APDU_SW_CONDITIONS_NOT_SATISFIED = 0x000A6985,
        UFR_APDU_SW_WRONG_DATA = 0x000A6A80,
        UFR_APDU_SW_FILE_NOT_FOUND = 0x000A6A82,
        UFR_APDU_SW_RECORD_NOT_FOUND = 0x000A6A83,
        UFR_APDU_SW_DATA_NOT_FOUND = 0x000A6A88,
        UFR_APDU_SW_ENTITY_ALREADY_EXISTS = 0x000A6A89,
        UFR_APDU_SW_INS_NOT_SUPPORTED = 0x000A6D00,
        UFR_APDU_SW_NO_PRECISE_DIAGNOSTIC = 0x000A6F00,

        MAX_UFR_STATUS = 0x7FFFFFFF

    }

    public enum tag_type_t
    {
        STR = 10,
        LANGUAGE_CODE_PAIRS,
        BCD_4BY4,
        DEC_UINT8,
        DEC_UINT16,
        DEC_UINT32,
        ISO3166_COUNTRY,
        ISO4217_CURRENCY,
        DATE_YMD,
        BIN_OR_STR,
        BIN,
        //-------------------
        TL_LIST,
        NODE,
    }

    public class iso4217_currency_code_s
    {
        public ushort num_code;

        public string alpha_code;

        public string currency;

        public iso4217_currency_code_s(ushort num_code_init, string alpha_code_init, string currency_init)
        {
            num_code = num_code_init;

            alpha_code = alpha_code_init;

            currency = currency_init;
        }
    }

    public class emv_tags_s
    {
        public emv_tag_t tag;

        public string description;

        public tag_type_t tag_type;

        public byte tag_id_len;

        public emv_tags_s(emv_tag_t tag_init, string init_desc, tag_type_t init_tag_type, byte init_tag_id_len)
        {
            tag = tag_init;

            description = init_desc;

            tag_type = init_tag_type;

            tag_id_len = init_tag_id_len;
        }

    }

    public class emv_tree_node_t : emv_tree_node_s { };

    public class emv_tree_node_s
    {
        public int[] tag = new int[1];

        public byte[] tag_bytes = new byte[1];

        public String description = "";

        public tag_type_t tag_type;

        public bool[] is_node_type = new bool[1];

        public byte[] value = new byte[1024];

        public int[] value_len = new int[1];

        public emv_tree_node_t tl_list_format;

        public emv_tree_node_t next;

        public emv_tree_node_t subnode;
    }

    public class afl_list_item_t : afl_list_item_s { };

    public class afl_list_item_s
    {
        public byte[] sfi = new byte[1];

        public byte[] record_first = new byte[1];

        public byte[] record_last = new byte[1];

        public byte[] record_num_offline_auth = new byte[1];

        public afl_list_item_t next;

    }

    public class uFCoder
    {

#if WIN64

        const string DLL_PATH = "..\\..\\ufr-lib\\windows\\x86_64\\";
        const string NAME_DLL = "uFCoder-x86_64.dll";

#else
        const string DLL_PATH = "..\\..\\ufr-lib\\windows\\x86\\";
      
        const string NAME_DLL = "uFCoder-x86.dll";
      

#endif
        const string DLL_NAME = DLL_PATH + NAME_DLL;
        

        public int MAX_TAG_LEN_BYTES = 3;
        

        public static emv_tags_s[] emv_tags = {
        new emv_tags_s(0x9f01, "Acquirer Identifier", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f02, "Amount, Authorised (Numeric)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f03, "Amount, Other (Numeric)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f04, "Amount, Other (Binary)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f05, "Application Discretionary Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f06, "Application Identifier (AID) - terminal", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f07, "Application Usage Control", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f08, "Application Version Number", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f09, "Application Version Number", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f0b, "Cardholder Name Extended", tag_type_t.BIN, 2),
        new emv_tags_s(0xbf0c, "FCI Issuer Discretionary Data", tag_type_t.NODE, 2),
        new emv_tags_s(0x9f0d, "Issuer Action Code - Default", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f0e, "Issuer Action Code - Denial", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f0f, "Issuer Action Code - Online", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f10, "Issuer Application Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f11, "Issuer Code Table Index", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f12, "Application Preferred Name", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f13, "Last Online Application Transaction Counter (ATC) Register", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f14, "Lower Consecutive Offline Limit", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f15, "Merchant Category Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f16, "Merchant Identifier", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f17, "Personal Identification Number (PIN) Try Counter", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f18, "Issuer Script Identifier", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f1a, "Terminal Country Code", tag_type_t.ISO3166_COUNTRY, 2),
        new emv_tags_s(0x9f1b, "Terminal Floor Limit", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f1c, "Terminal Identification", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f1d, "Terminal Risk Management Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f1e, "Interface Device (IFD) Serial Number", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f1f, "Track 1 Discretionary Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f20, "Cardholder Name", tag_type_t.STR, 2),
        new emv_tags_s(0x9f21, "Transaction Time", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f22, "Certification Authority Public Key Index", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f23, "Upper Consecutive Offline Limit", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f24, "Application Expiration Date", tag_type_t.DATE_YMD, 2),
        new emv_tags_s(0x5f25, "Application Effective Date", tag_type_t.DATE_YMD, 2),
        new emv_tags_s(0x9f26, "Application Cryptogram", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f27, "Cryptogram Information Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f28, "Issuer Country Code", tag_type_t.ISO3166_COUNTRY, 2),
        new emv_tags_s(0x5f2a, "Transaction Currency Code", tag_type_t.ISO4217_CURRENCY, 2),
        new emv_tags_s(0x5f2d, "Language Preference", tag_type_t.LANGUAGE_CODE_PAIRS, 2),
        new emv_tags_s(0x9f2e, "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f2f, "Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f30, "Service Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f32, "Issuer Public Key Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f33, "Terminal Capabilities", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f34, "Application PAN Sequence Number (PSN)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f35, "Terminal Type", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f36, "Transaction Currency Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f37, "Unpredictable Number", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f38, "Processing Options Data Object List (PDOL)", tag_type_t.TL_LIST, 2),
        new emv_tags_s(0x9f34, "Cardholder Verification Method (CVM) Results", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f3a, "Amount, Reference Currency", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f3b, "Application Reference Currency", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f3c, "Transaction Reference Currency Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f3d, "Transaction Reference Currency Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f40, "Additional Terminal Capabilities", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f41, "Transaction Sequence Counter", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f43, "Application Reference Currency Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f44, "Application Currency Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f2d, "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f46, "Integrated Circuit Card (ICC) Public Key Certificate", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f47, "Integrated Circuit Card (ICC) Public Key Exponent", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f48, "Integrated Circuit Card (ICC) Public Key Remainder", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f49, "Dynamic Data Authentication Data Object List (DDOL)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f4a, "Static Data Authentication Tag List", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f4b, "Signed Dynamic Application Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f4c, "ICC Dynamic Number", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f4d, "Log Entry", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f4e, "Merchant Name and Location", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f51, "Application Currency Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f52, "Card Verification Results (CVR)", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f53, "International Bank Account Number (IBAN)", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f54, "Bank Identifier Code (BIC)", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f55, "Issuer Country Code (alpha2 format)", tag_type_t.BIN, 2),
        new emv_tags_s(0x5f56, "Issuer Country Code (alpha3 format)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f58, "Lower Consecutive Offline Limit (Card Check)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f59, "Upper Consecutive Offline Limit (Card Check)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f5c, "Cumulative Total Transaction Amount Upper Limit", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f72, "Consecutive Transaction Limit (International - Country)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f7c, "Merchant Custom Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9F62, "PCVC3 (Track1)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9F63, "PUNATC (Track1)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9F64, "NATC (Track1)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f65, "Track 2 Bit Map for CVC3", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f66, "Terminal Transaction Qualifiers (TTQ)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f67, "NATC (Track2)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f68, "Mag Stripe CVM List", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f69, "Unpredictable Number Data Object List (UDOL)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f6b, "Track 2 Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f6c, "Mag Stripe Application Version Number (Card)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f6e, "Third Party Data", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f74, "VLP Issuer Authorization Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f75, "Cumulative Total Transaction Amount Limit - Dual Currency", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f76, "Secondary Application Currency Code", tag_type_t.ISO4217_CURRENCY, 2),
        new emv_tags_s(0x9f7d, "Unknown Tag", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f7f, "Card Production Life Cycle (CPLC) History File Identifiers", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f45, "Data Authentication Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f57, "Issuer Country Code", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f39, "Point-of-Service (POS) Entry Mode", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f73, "Currency Conversion Factor", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f42, "Application Currency Code", tag_type_t.ISO4217_CURRENCY, 2),
        new emv_tags_s(0x9f56, "Issuer Authentication Indicator", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f20, "Track 2 Discretionary Data", tag_type_t.BIN, 2),
        new emv_tags_s(0xdf01, "Reference PIN", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f36, "Application Transaction Counter (ATC)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f4f, "Log Format", tag_type_t.TL_LIST, 2),
        new emv_tags_s(0x5f50, "Issuer URL", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f5a, "Issuer URL2", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f53, "Consecutive Transaction Limit (International)", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f54, "Cumulative Total Transaction Amount Limit", tag_type_t.BIN, 2),
        new emv_tags_s(0x9f55, "Geographic Indicator", tag_type_t.BIN, 2),
        new emv_tags_s(0x42, "Issuer Identification Number (IIN)", tag_type_t.BIN, 1),
        new emv_tags_s(0x4f, "Application Identifier (AID)", tag_type_t.BIN, 1),
        new emv_tags_s(0x50, "Application Label", tag_type_t.STR, 1),
        new emv_tags_s(0x56, "Track 1 Equivalent Data", tag_type_t.BIN, 1),
        new emv_tags_s(0x57, "Track 2 Equivalent Data", tag_type_t.BIN, 1),
        new emv_tags_s(0x5a, "Application Primary Account Number (PAN)", tag_type_t.BCD_4BY4, 1),
        new emv_tags_s(0x61, "Application Template", tag_type_t.NODE, 1),
        new emv_tags_s(0x6f, "File Control Information (FCI) Template", tag_type_t.NODE, 1),
        new emv_tags_s(0x70, "Response Message Template / AEF Data Template", tag_type_t.NODE, 1),
        new emv_tags_s(0x71, "Issuer Script Template 1", tag_type_t.BIN, 1),
        new emv_tags_s(0x72, "Issuer Script Template 2", tag_type_t.BIN, 1),
        new emv_tags_s(0x73, "Directory Discretionary Template", tag_type_t.BIN, 1),
        new emv_tags_s(0x77, "Response Message Template Format 2", tag_type_t.NODE, 1),
        new emv_tags_s(0x80, "Response Message Template Format 1", tag_type_t.BIN, 1),
        new emv_tags_s(0x81, "Amount, Authorised (Binary)", tag_type_t.BIN, 1),
        new emv_tags_s(0x82, "Application Interchange Profile (AIP)", tag_type_t.BIN, 1),
        new emv_tags_s(0x83, "Command Template", tag_type_t.BIN, 1),
        new emv_tags_s(0x84, "Dedicated File (DF) Name", tag_type_t.BIN_OR_STR, 1),
        new emv_tags_s(0x86, "Issuer Script Command", tag_type_t.BIN, 1),
        new emv_tags_s(0x87, "Application Priority Indicator", tag_type_t.BIN, 1),
        new emv_tags_s(0x88, "Short File Identifier (SFI)", tag_type_t.BIN, 1),
        new emv_tags_s(0x89, "Authorisation Code", tag_type_t.BIN, 1),
        new emv_tags_s(0x8a, "Authorisation Response Code", tag_type_t.BIN, 1),
        new emv_tags_s(0x8c, "Card Risk Management Data Object List 1 (CDOL1)", tag_type_t.BIN, 1),
        new emv_tags_s(0x8d, "Card Risk Management Data Object List 2 (CDOL2)", tag_type_t.BIN, 1),
        new emv_tags_s(0x8e, "Cardholder Verification Method (CVM) List", tag_type_t.BIN, 1),
        new emv_tags_s(0x8f, "Certification Authority Public Key Index", tag_type_t.BIN, 1),
        new emv_tags_s(0x90, "Issuer Public Key Certificate", tag_type_t.BIN, 1),
        new emv_tags_s(0x91, "Issuer Authentication Data", tag_type_t.BIN, 1),
        new emv_tags_s(0x92, "Issuer Public Key Remainder", tag_type_t.BIN, 1),
        new emv_tags_s(0x93, "Signed Static Application Data", tag_type_t.BIN, 1),
        new emv_tags_s(0x94, "Application File Locator (AFL)", tag_type_t.BIN, 1),
        new emv_tags_s(0x95, "Terminal Verification Results", tag_type_t.BIN, 1),
        new emv_tags_s(0x97, "Transaction Certificate Data Object List (TDOL)", tag_type_t.BIN, 1),
        new emv_tags_s(0x98, "Transaction Certificate (TC) Hash Value", tag_type_t.BIN, 1),
        new emv_tags_s(0x99, "Transaction Personal Identification Number (PIN) Data", tag_type_t.BIN, 1),
        new emv_tags_s(0x9a, "Transaction Date", tag_type_t.DATE_YMD, 1),
        new emv_tags_s(0x9b, "Transaction Status Information", tag_type_t.BIN, 1),
        new emv_tags_s(0x9c, "Transaction Type", tag_type_t.BIN, 1),
        new emv_tags_s(0x9d, "Directory Definition File (DDF) Name", tag_type_t.BIN, 1),
        new emv_tags_s(0xa5, "File Control Information (FCI) Proprietary Template", tag_type_t.NODE, 1),
        new emv_tags_s(0, "UNKNOWN TAG", tag_type_t.BIN, 0)
        };


        public iso4217_currency_code_s[] iso4217_currency_codes =
        {
            new iso4217_currency_code_s( 8,   "ALL", "Albania Lek"),
            new iso4217_currency_code_s( 12,  "DZD", "Algeria Dinar" ),
            new iso4217_currency_code_s( 32,  "ARS", "Argentina Peso" ),
            new iso4217_currency_code_s( 36,  "AUD", "Australia Dollar" ),
            new iso4217_currency_code_s( 44,  "BSD", "Bahamas Dollar" ),
            new iso4217_currency_code_s( 48,  "BHD", "Bahrain Dinar" ),
            new iso4217_currency_code_s( 50,  "BDT", "Bangladesh Taka" ),
            new iso4217_currency_code_s( 51,  "AMD", "Armenia Dram" ),
            new iso4217_currency_code_s( 52,  "BBD", "Barbados Dollar" ),
            new iso4217_currency_code_s( 60,  "BMD", "Bermuda Dollar" ),
            new iso4217_currency_code_s( 64,  "BTN", "Bhutan Ngultrum" ),
            new iso4217_currency_code_s( 68,  "BOB", "Bolivia Bolíviano" ),
            new iso4217_currency_code_s( 72,  "BWP", "Botswana Pula" ),
            new iso4217_currency_code_s( 84,  "BZD", "Belize Dollar" ),
            new iso4217_currency_code_s( 90,  "SBD", "Solomon Islands Dollar" ),
            new iso4217_currency_code_s( 96,  "BND", "Brunei Darussalam Dollar" ),
            new iso4217_currency_code_s( 104, "MMK", "Myanmar (Burma) Kyat" ),
            new iso4217_currency_code_s( 108, "BIF", "Burundi Franc" ),
            new iso4217_currency_code_s( 116, "KHR", "Cambodia Riel" ),
            new iso4217_currency_code_s( 124, "CAD", "Canada Dollar" ),
            new iso4217_currency_code_s( 132, "CVE", "Cape Verde Escudo" ),
            new iso4217_currency_code_s( 136, "KYD", "Cayman Islands Dollar" ),
            new iso4217_currency_code_s( 144, "LKR", "Sri Lanka Rupee" ),
            new iso4217_currency_code_s( 152, "CLP", "Chile Peso" ),
            new iso4217_currency_code_s( 156, "CNY", "China Yuan Renminbi" ),
            new iso4217_currency_code_s( 170, "COP", "Colombia Peso" ),
            new iso4217_currency_code_s( 174, "KMF", "Comorian Franc" ),
            new iso4217_currency_code_s( 188, "CRC", "Costa Rica Colon" ),
            new iso4217_currency_code_s( 191, "HRK", "Croatia Kuna" ),
            new iso4217_currency_code_s( 192, "CUP", "Cuba Peso" ),
            new iso4217_currency_code_s( 203, "CZK", "Czech Republic Koruna" ),
            new iso4217_currency_code_s( 208, "DKK", "Denmark Krone" ),
            new iso4217_currency_code_s( 214, "DOP", "Dominican Republic Peso" ),
            new iso4217_currency_code_s( 222, "SVC", "El Salvador Colon" ),
            new iso4217_currency_code_s( 230, "ETB", "Ethiopia Birr" ),
            new iso4217_currency_code_s( 232, "ERN", "Eritrea Nakfa" ),
            new iso4217_currency_code_s( 238, "FKP", "Falkland Islands (Malvinas) Pound" ),
            new iso4217_currency_code_s( 242, "FJD", "Fiji Dollar" ),
            new iso4217_currency_code_s( 262, "DJF", "Djibouti Franc" ),
            new iso4217_currency_code_s( 270, "GMD", "Gambia Dalasi" ),
            new iso4217_currency_code_s( 292, "GIP", "Gibraltar Pound" ),
            new iso4217_currency_code_s( 320, "GTQ", "Guatemala Quetzal" ),
            new iso4217_currency_code_s( 324, "GNF", "Guinea Franc" ),
            new iso4217_currency_code_s( 328, "GYD", "Guyana Dollar" ),
            new iso4217_currency_code_s( 332, "HTG", "Haiti Gourde" ),
            new iso4217_currency_code_s( 340, "HNL", "Honduras Lempira" ),
            new iso4217_currency_code_s( 344, "HKD", "Hong Kong Dollar" ),
            new iso4217_currency_code_s( 348, "HUF", "Hungary Forint" ),
            new iso4217_currency_code_s( 352, "ISK", "Iceland Krona" ),
            new iso4217_currency_code_s( 356, "INR", "India Rupee" ),
            new iso4217_currency_code_s( 360, "IDR", "Indonesia Rupiah" ),
            new iso4217_currency_code_s( 364, "IRR", "Iran Rial" ),
            new iso4217_currency_code_s( 368, "IQD", "Iraq Dinar" ),
            new iso4217_currency_code_s( 376, "ILS", "Israel Shekel" ),
            new iso4217_currency_code_s( 388, "JMD", "Jamaica Dollar" ),
            new iso4217_currency_code_s( 392, "JPY", "Japan Yen" ),
            new iso4217_currency_code_s( 398, "KZT", "Kazakhstan Tenge" ),
            new iso4217_currency_code_s( 400, "JOD", "Jordan Dinar" ),
            new iso4217_currency_code_s( 404, "KES", "Kenya Shilling" ),
            new iso4217_currency_code_s( 408, "KPW", "Korea (North) Won" ),
            new iso4217_currency_code_s( 410, "KRW", "Korea (South) Won" ),
            new iso4217_currency_code_s( 414, "KWD", "Kuwait Dinar" ),
            new iso4217_currency_code_s( 417, "KGS", "Kyrgyzstan Som" ),
            new iso4217_currency_code_s( 418, "LAK", "Laos Kip" ),
            new iso4217_currency_code_s( 422, "LBP", "Lebanon Pound" ),
            new iso4217_currency_code_s( 426, "LSL", "Lesotho Loti" ),
            new iso4217_currency_code_s( 430, "LRD", "Liberia Dollar" ),
            new iso4217_currency_code_s( 434, "LYD", "Libya Dinar" ),
            new iso4217_currency_code_s( 446, "MOP", "Macau Pataca" ),
            new iso4217_currency_code_s( 454, "MWK", "Malawi Kwacha" ),
            new iso4217_currency_code_s( 458, "MYR", "Malaysia Ringgit" ),
            new iso4217_currency_code_s( 462, "MVR", "Maldives (Maldive Islands) Rufiyaa" ),
            new iso4217_currency_code_s( 478, "MRO", "Mauritania Ouguiya" ),
            new iso4217_currency_code_s( 480, "MUR", "Mauritius Rupee" ),
            new iso4217_currency_code_s( 484, "MXN", "Mexico Peso" ),
            new iso4217_currency_code_s( 496, "MNT", "Mongolia Tughrik" ),
            new iso4217_currency_code_s( 498, "MDL", "Moldova Leu" ),
            new iso4217_currency_code_s( 504, "MAD", "Morocco Dirham" ),
            new iso4217_currency_code_s( 512, "OMR", "Oman Rial" ),
            new iso4217_currency_code_s( 516, "NAD", "Namibia Dollar" ),
            new iso4217_currency_code_s( 524, "NPR", "Nepal Rupee" ),
            new iso4217_currency_code_s( 532, "ANG", "Netherlands Antilles Guilder" ),
            new iso4217_currency_code_s( 533, "AWG", "Aruba Guilder" ),
            new iso4217_currency_code_s( 548, "VUV", "Vanuatu Vatu" ),
            new iso4217_currency_code_s( 554, "NZD", "New Zealand Dollar" ),
            new iso4217_currency_code_s( 558, "NIO", "Nicaragua Cordoba" ),
            new iso4217_currency_code_s( 566, "NGN", "Nigeria Naira" ),
            new iso4217_currency_code_s( 578, "NOK", "Norway Krone" ),
            new iso4217_currency_code_s( 586, "PKR", "Pakistan Rupee" ),
            new iso4217_currency_code_s( 590, "PAB", "Panama Balboa" ),
            new iso4217_currency_code_s( 598, "PGK", "Papua New Guinea Kina" ),
            new iso4217_currency_code_s( 600, "PYG", "Paraguay Guarani" ),
            new iso4217_currency_code_s( 604, "PEN", "Peru Sol" ),
            new iso4217_currency_code_s( 608, "PHP", "Philippines Peso" ),
            new iso4217_currency_code_s( 634, "QAR", "Qatar Riyal" ),
            new iso4217_currency_code_s( 643, "RUB", "Russia Ruble" ),
            new iso4217_currency_code_s( 646, "RWF", "Rwanda Franc" ),
            new iso4217_currency_code_s( 654, "SHP", "Saint Helena Pound" ),
            new iso4217_currency_code_s( 678, "STD", "Sao Tome and Principe dobra" ),
            new iso4217_currency_code_s( 682, "SAR", "Saudi Arabia Riyal" ),
            new iso4217_currency_code_s( 690, "SCR", "Seychelles Rupee" ),
            new iso4217_currency_code_s( 694, "SLL", "Sierra Leone Leone" ),
            new iso4217_currency_code_s( 702, "SGD", "Singapore Dollar" ),
            new iso4217_currency_code_s( 704, "VND", "Viet Nam Dong" ),
            new iso4217_currency_code_s( 706, "SOS", "Somalia Shilling" ),
            new iso4217_currency_code_s( 710, "ZAR", "South Africa Rand" ),
            new iso4217_currency_code_s( 728, "SSP", "South Sudanese pound" ),
            new iso4217_currency_code_s( 748, "SZL", "Swaziland Lilangeni" ),
            new iso4217_currency_code_s( 752, "SEK", "Sweden Krona" ),
            new iso4217_currency_code_s( 756, "CHF", "Switzerland Franc" ),
            new iso4217_currency_code_s( 760, "SYP", "Syria Pound" ),
            new iso4217_currency_code_s( 764, "THB", "Thailand Baht" ),
            new iso4217_currency_code_s( 776, "TOP", "Tonga Pa‘anga" ),
            new iso4217_currency_code_s( 780, "TTD", "Trinidad and Tobago Dollar" ),
            new iso4217_currency_code_s( 784, "AED", "United Arab Emirates Dirham" ),
            new iso4217_currency_code_s( 788, "TND", "Tunisia Dinar" ),
            new iso4217_currency_code_s( 800, "UGX", "Uganda Shilling" ),
            new iso4217_currency_code_s( 807, "MKD", "Macedonia Denar" ),
            new iso4217_currency_code_s( 818, "EGP", "Egypt Pound" ),
            new iso4217_currency_code_s( 826, "GBP", "United Kingdom Pound" ),
            new iso4217_currency_code_s( 834, "TZS", "Tanzania Shilling" ),
            new iso4217_currency_code_s( 840, "USD", "United States Dollar" ),
            new iso4217_currency_code_s( 858, "UYU", "Uruguay Peso" ),
            new iso4217_currency_code_s( 860, "UZS", "Uzbekistan Som" ),
            new iso4217_currency_code_s( 882, "WST", "Samoa Tala" ),
            new iso4217_currency_code_s( 886, "YER", "Yemen Rial" ),
            new iso4217_currency_code_s( 901, "TWD", "Taiwan New Dollar" ),
            new iso4217_currency_code_s( 931, "CUC", "Cuba Convertible Peso" ),
            new iso4217_currency_code_s( 932, "ZWL", "Zimbabwe Dollar" ),
            new iso4217_currency_code_s( 933, "BYN", "Belarus Ruble" ),
            new iso4217_currency_code_s( 934, "TMT", "Turkmenistan Manat" ),
            new iso4217_currency_code_s( 936, "GHS", "Ghana Cedi" ),
            new iso4217_currency_code_s( 937, "VEF", "Venezuela Bolívar" ),
            new iso4217_currency_code_s( 938, "SDG", "Sudan Pound" ),
            new iso4217_currency_code_s( 941, "RSD", "Serbia Dinar" ),
            new iso4217_currency_code_s( 943, "MZN", "Mozambique Metical" ),
            new iso4217_currency_code_s( 944, "AZN", "Azerbaijan Manat" ),
            new iso4217_currency_code_s( 946, "RON", "Romania Leu" ),
            new iso4217_currency_code_s( 949, "TRY", "Turkey Lira" ),
            new iso4217_currency_code_s( 950, "XAF", "CFA franc BEAC" ),
            new iso4217_currency_code_s( 951, "XCD", "East Caribbean Dollar" ),
            new iso4217_currency_code_s( 952, "XOF", "CFA franc BCEAO" ),
            new iso4217_currency_code_s( 953, "XPF", "CFP franc (franc Pacifique)" ),
            new iso4217_currency_code_s( 960, "XDR", "IMF Special Drawing Rights" ),
            new iso4217_currency_code_s( 967, "ZMW", "Zambia Kwacha" ),
            new iso4217_currency_code_s( 968, "SRD", "Suriname Dollar" ),
            new iso4217_currency_code_s( 969, "MGA", "Madagascar Ariary" ),
            new iso4217_currency_code_s( 971, "AFN", "Afghanistan Afghani" ),
            new iso4217_currency_code_s( 972, "TJS", "Tajikistan Somoni" ),
            new iso4217_currency_code_s( 973, "AOA", "Angola Kwanza" ),
            new iso4217_currency_code_s( 975, "BGN", "Bulgaria Lev" ),
            new iso4217_currency_code_s( 976, "CDF", "Congo/Kinshasa Franc" ),
            new iso4217_currency_code_s( 977, "BAM", "Bosnia and Herzegovina Convertible Marka" ),
            new iso4217_currency_code_s( 978, "EUR", "Euro" ),
            new iso4217_currency_code_s( 980, "UAH", "Ukraine Hryvnia" ),
            new iso4217_currency_code_s( 981, "GEL", "Georgia Lari" ),
            new iso4217_currency_code_s( 985, "PLN", "Poland Zloty" ),
            new iso4217_currency_code_s( 986, "BRL", "Brazil Real" ),
            new iso4217_currency_code_s( 0, "---", "Unknown currency")
    };

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReaderOpen")]
        public static extern DL_STATUS ReaderOpen();

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "ReaderOpenEx")]
        private static extern DL_STATUS ReaderOpenEx(UInt32 reader_type, [In] byte[] port_name, UInt32 port_interface, [In] byte[] arg);
        public static DL_STATUS ReaderOpenEx(UInt32 reader_type, string port_name, UInt32 port_interface, string arg)
        {

            byte[] port_name_p = Encoding.ASCII.GetBytes(port_name);
            byte[] port_name_param = new byte[port_name_p.Length + 1];
            Array.Copy(port_name_p, 0, port_name_param, 0, port_name_p.Length);
            port_name_param[port_name_p.Length] = 0;

            byte[] arg_p = Encoding.ASCII.GetBytes(arg);
            byte[] arg_param = new byte[arg_p.Length + 1];
            Array.Copy(arg_p, 0, arg_param, 0, arg_p.Length);
            arg_param[arg_p.Length] = 0;

            return ReaderOpenEx(reader_type, port_name_param, port_interface, arg_param);
        }

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReaderClose")]
        public static extern DL_STATUS ReaderClose();

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReaderReset")]
        public static extern DL_STATUS ReaderReset();

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReaderSoftRestart")]
        public static extern DL_STATUS ReaderSoftRestart();

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetReaderType")]
        public static extern DL_STATUS GetReaderType(out ulong get_reader_type);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReaderKeyWrite")]
        public static extern DL_STATUS ReaderKeyWrite(out byte aucKey, byte ucKeyIndex);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetReaderSerialNumber")]
        public static extern DL_STATUS GetReaderSerialNumber(out ulong serial_number);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetCardId")]
        public static extern DL_STATUS GetCardId(out byte card_type, out ulong card_serial);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetCardIdEx")]
        public static extern DL_STATUS GetCardIdEx(out byte bCardType,
                                                   out byte bCardUid,
                                                   out byte bUidSize);
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetDlogicCardType")]
        public static extern DL_STATUS GetDlogicCardType(out byte bCardType);
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReaderUISignal")]
        public static extern DL_STATUS ReaderUISignal(int light_mode, int sound_mode);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "ReadUserData")]
        public static extern DL_STATUS ReadUserData(out byte aucData);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "WriteUserData")]
        public static extern DL_STATUS WriteUserData(out byte aucData);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetReaderHardwareVersion")]
        public static extern DL_STATUS GetReaderHardwareVersion(out byte bVerMajor,
                                                                out byte bVerMinor);
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetReaderFirmwareVersion")]
        public static extern DL_STATUS GetReaderFirmwareVersion(out byte bVerMajor,
                                                               out byte bVerMinor);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetReaderSerialDescription")]
        public static extern DL_STATUS GetReaderSerialDescription(byte[] SerialDescription);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "GetBuildNumber")]
        public static extern DL_STATUS GetBuildNumber(out byte build);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "UFR_Status2String")]
        private static extern IntPtr UFR_Status2String(DL_STATUS status);
        public static string status2str(DL_STATUS status)
        {
            IntPtr str_ret = UFR_Status2String(status);
            return Marshal.PtrToStringAnsi(str_ret);
        }

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetDllVersionStr")]
        private static extern IntPtr GetDllVersionStr();
        public static string GetLibraryVersion()
        {
            IntPtr str_ret = GetDllVersionStr();
            return Marshal.PtrToStringAnsi(str_ret);
        }

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetISO14443_4_Mode")]
        public static extern DL_STATUS SetISO14443_4_Mode();

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "APDUTransceive")]
        public static extern DL_STATUS APDUTransceive(byte cls, byte ins, byte p1, byte p2, char[] data_out, int Nc, byte[] data_in, int[] Ne,
             byte send_le, byte[] apdu_status);


        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "APDUTransceive")]
        public static extern DL_STATUS APDUTransceive_Bytes(byte cls, byte ins, byte p1, byte p2, byte[] data_out, int Nc, byte[] data_in, int[] Ne,
             byte send_le, byte[] apdu_status);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "s_block_deselect")]
        public static extern DL_STATUS s_block_deselect(byte timeout);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, EntryPoint = "EMV_GetPAN")]
        private static extern DL_STATUS EMV_GetPAN([In] byte[] df_name, [Out] byte[] pan_str);
        public static DL_STATUS EMV_GetPAN(string df_name, [Out] byte[] pan_str)
        {
            byte[] df_name_p = Encoding.ASCII.GetBytes(df_name);
            byte[] df_name_param = new byte[df_name_p.Length + 1];
            Array.Copy(df_name_p, 0, df_name_param, 0, df_name_p.Length);
            df_name_param[df_name_p.Length] = 0;

            return EMV_GetPAN(df_name_param, pan_str);
        }

        //---------------------------------------------------------------------------------------------------------------------------------
        //--------------------------------------- EMV FUNCTION ----------------------------------------------------------------------------
        //---------------------------------------------------------------------------------------------------------------------------------

        public static int getSfi(emv_tree_node_t tag_node, byte[] sfi)
        {
            if (!tag_node.is_node_type[0])
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;

            if (tag_node.tag[0] == 0x88)
            {
                if (tag_node.value_len[0] == 1)
                {
                    sfi[0] = (byte)tag_node.value[0];
                    return (int)UFR_STATUS.UFR_OK;
                }
                else
                {
                    return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_SIZE;
                }
            }
            else
            {
                if (tag_node.subnode != null)
                {
                    return getSfi(tag_node.subnode, sfi);
                }
                else
                {

                    return getSfi(tag_node.next, sfi);
                }
            }
        }

        //--------------------------------------------------------------------

        public static int getAid(emv_tree_node_t tag_node, byte[] aid, byte[] aid_len)
        {
            int status;
            while (tag_node.value_len[0] != 0)
            {
                status = getAid__(tag_node, aid, aid_len);
                if (status == (int)UFR_STATUS.UFR_OK)
                {
                    return (int)UFR_STATUS.UFR_OK;
                }
                tag_node = tag_node.next;
            }

            return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;
        }

        //--------------------------------------------------------------------

        public static int getAid__(emv_tree_node_t tag_node, byte[] aid, byte[] aid_len)
        {
            if (tag_node.value_len[0] == 0)
            {
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;
            }

            if (tag_node.tag[0] == 0x4F)
            {
                if (tag_node.value_len[0] < 17)
                {

                    aid_len[0] = (byte)tag_node.value_len[0];
                    
                    Array.Copy(tag_node.value, 0, aid, 0, tag_node.value_len[0]);
                    

                    return (int)UFR_STATUS.UFR_OK;
                }
                else
                {
                    return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_SIZE;
                }
            }
            else
            {
                if (tag_node.subnode != null)
                {
                    return getAid__(tag_node.subnode, aid, aid_len);
                }
                else
                {
                    return getAid__(tag_node.next, aid, aid_len);
                }
            }

        }

        //--------------------------------------------------------------------

        public static int getLogEntry(emv_tree_node_s tag_node, byte[] sfi, byte[] log_records)
        {
            int status;

            while (tag_node.value_len[0] > 0)
            {
                status = getLogEntry__(tag_node, sfi, log_records);
                if (status == (int) UFR_STATUS.UFR_OK)
                {
                    return (int)UFR_STATUS.UFR_OK;
                }
                tag_node = tag_node.next;
            }
            return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;
        }

        //--------------------------------------------------------------------

        public static int getLogEntry__(emv_tree_node_s tag_node, byte[] sfi, byte[] log_records)
        {


            if (tag_node.description == "")
            {
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;
            }
            if (tag_node.tag[0] == (int)0x9F4D)
            {
                if (tag_node.value_len[0] == 2)
                {
                    sfi[0] = (byte)tag_node.value[0];
                    log_records[0] = (byte)tag_node.value[1];
                    return (int)UFR_STATUS.UFR_OK;
                }
                else
                {
                    return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_SIZE;
                }
            }
            else
            {
                if (tag_node.subnode != null)
                {
                    return getLogEntry__(tag_node.subnode, sfi, log_records);
                }
                else
                {
                    return getLogEntry__(tag_node.next, sfi, log_records);
                }
            }
        }

        //--------------------------------------------------------------------

        public static int getListLength(emv_tree_node_t tag_node, short[] length)
        {

            emv_tree_node_t p = new emv_tree_node_t();

            length[0] = 0;

            if (tag_node.description == "")
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;
            if (tag_node.tag_type != tag_type_t.TL_LIST)
                return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_TYPE;
            if (tag_node.tl_list_format.value_len[0] == 0)
            {
                return (int)UFR_STATUS.EMV_ERR_LIST_FORMAT_NOT_FOUND;
            }

            p = tag_node.tl_list_format;

            while (p != null)
            {
                length[0] += (short)p.value_len[0];
                p = p.next;
            }
            return (int)UFR_STATUS.UFR_OK;
        }

        //--------------------------------------------------------------------

        public static int getAfl(emv_tree_node_t tag_node, afl_list_item_t[] afl_list_item, byte[] afl_list_count)
        {

            if (tag_node == null)
            {
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;
            }

            byte items = 0;
            byte[] value_ptr = new byte[tag_node.value_len[0]];
            afl_list_item_t[] temp = new afl_list_item_t[1];
            afl_list_item_t[] p = new afl_list_item_t[1];

            int status;

            afl_list_count[0] = 0;


            if (tag_node.tag[0] == (int)0x94)
            {
                if ((tag_node.value_len[0] == 0) || ((tag_node.value_len[0] % 4) > 0)) //first 2 bytes are AIP
                    return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_SIZE;
                else
                {
                    items = (byte)(tag_node.value_len[0] / 4);
                    value_ptr = tag_node.value;
                    //System.arraycopy(tag_node.value, 0, value_ptr, 0, tag_node.value_len[0]);
                    Array.Copy(tag_node.value, 0, value_ptr, 0, tag_node.value_len[0]);

                    byte ptr_val = 0;
                    while (items > 0)
                    {

                        status = newAflListItem(p);
                        if (afl_list_item[0] == null)
                        {
                            if (status > 0)
                            {
                                return status;
                            }
                            afl_list_item[0] = p[0];
                            temp[0] = p[0];
                        }
                        else
                        {
                            if (status > 0)
                            {
                                emvAflListCleanup(afl_list_item[0]);
                                afl_list_item[0] = null;
                                return status;
                            }
                            temp[0].next = p[0];
                            temp[0] = temp[0].next;
                        }

                        p[0].sfi[0] = value_ptr[ptr_val++];
                        p[0].sfi[0] >>= 3;
                        p[0].record_first[0] = value_ptr[ptr_val++];
                        p[0].record_last[0] = value_ptr[ptr_val++];
                        p[0].record_num_offline_auth[0] = value_ptr[ptr_val++];

                        items--;
                    }

                    afl_list_count[0] = (byte)(tag_node.value_len[0] / 4);


                    return (int)UFR_STATUS.UFR_OK;

                }

            }
            else
            {
                if (tag_node.subnode != null)
                {
                    return getAfl(tag_node.subnode, afl_list_item, afl_list_count);
                }
                else
                {
                    return getAfl(tag_node.next, afl_list_item, afl_list_count);
                }
            }
        }

        //--------------------------------------------------------------------

        public static int getAflFromResponseMessageTemplateFormat1(emv_tree_node_t tag_node, afl_list_item_t[] afl_list_item, byte[] afl_list_count)
        {

            if (tag_node == null)
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;

            byte items = 0, len = 0;
            byte[] value_ptr = new byte[tag_node.value_len[0]];

            bool first_item = true;
            afl_list_item_t temp = new afl_list_item_t();
            afl_list_item_t[] p = new afl_list_item_t[1];

            int status;

            afl_list_count[0] = 0;



            if (tag_node.tag[0] == 0x80)
            {
                len = (byte)(tag_node.value_len[0] - 2); // first 2 bytes are AIP
                if ((len == 0) || ((len % 4) == 0))
                { // first 2 bytes are AIP
                    return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_SIZE;
                }
                else
                {
                    items = (byte)(len / 4);
                    value_ptr = tag_node.value;  // first 2 bytes are AIP
                    byte ptr_val = value_ptr[0];
                    while (items > 0)
                    {
                        status = newAflListItem(p); // all members are cleared
                        if (first_item)
                        {
                            if (status > 0)
                                return status;
                            afl_list_item[0] = p[0];
                            temp = p[0];
                            first_item = false;
                        }
                        else
                        {
                            if (status > 0)
                            {
                                emvAflListCleanup(afl_list_item[0]);
                                return status;
                            }
                            afl_list_item[0].next = p[0];
                            afl_list_item[0] = afl_list_item[0].next;
                        }

                        p[0].sfi[0] = ptr_val++;
                        p[0].sfi[0] >>= 3;
                        p[0].record_first[0] = ptr_val++;
                        p[0].record_last[0] = ptr_val++;
                        p[0].record_num_offline_auth[0] = ptr_val++;

                        //System.arraycopy(value_ptr, 4, value_ptr, 0, value_ptr.length - 4);
                        Array.Copy(value_ptr, 4, value_ptr, 0, value_ptr.Length - 4);

                        items--;
                    }
                    afl_list_count[0] = (byte)(len / 4);
                    return (int)UFR_STATUS.UFR_OK;
                }
            }
            else
            {
                if (tag_node.subnode != null)
                {
                    return getAfl(tag_node.subnode, afl_list_item, afl_list_count);
                }
                else
                {
                    return getAfl(tag_node.next, afl_list_item, afl_list_count);
                }
            }
        }
        //------------------------------------------------------------------------------

        public static int newAflListItem(afl_list_item_t[] afl_list)
        {
            afl_list_item_t p = new afl_list_item_t();

            if (p == null)
            {
                return (int)UFR_STATUS.SYS_ERR_OUT_OF_MEMORY;
            }
            else
            {
                afl_list[0] = p;
            }

            p.sfi[0] = 0;
            p.record_first[0] = 0;
            p.record_last[0] = 0;
            p.record_num_offline_auth[0] = 0;
            p.next = null;

            afl_list[0] = p;

            return (int)UFR_STATUS.UFR_OK;
        }

        //--------------------------------------------------------------------

        public static void emvAflListCleanup(afl_list_item_s head)
        {
            afl_list_item_s temp;

            while (head.sfi[0] != 0)
            {
                temp = head.next;
                head = temp;
            }
        }

        //--------------------------------------------------------------------

        public static UFR_STATUS parseEmvTag(byte[] tag_ptr, int[] tag, byte[] tag_val, int[] tag_len, int[] tag_len_len, int[] tag_val_len)
        {
            byte ptr = 0;
            tag[0] = 0x00;
            tag[0] = (byte) tag_ptr[ptr++];

            tag_len[0] = 1;
            if ((tag[0] & 0x1F) == 0x1F)
            {
                tag[0] <<= 8;
                tag[0] |= tag_ptr[ptr];
                (tag_len[0])++;
                if ((tag_ptr[ptr++] & 0x80) == 0x80)
                {
                    tag[0] <<= 8;
                    tag[0] |= tag_ptr[ptr];
                    (tag_len[0])++;
                }
            }

            //Length
            tag_len_len[0] = 1;
            tag_val_len[0] = tag_ptr[ptr];
            if ((tag_ptr[ptr] & 0x80) == 0x80)
            {
                tag_len_len[0] += tag_ptr[ptr] & 0x7F;
            }
            if (tag_len_len[0] > 3)
            {
                return UFR_STATUS.EMV_ERR_MAX_TAG_LEN_BYTES_EXCEEDED;
            }

            if (tag_len_len[0] > 1)
            {
                tag_val_len[0] = 0;
                for (int i = tag_len_len[0] - 1; i > 0; i--)
                {
                    tag_val_len[0] |= tag_ptr[ptr++] << ((i - 1) * 8);
                }
            }

            ptr++;
            //tag_val = new byte[tag_val_len[0]];

            for (int i = 0; i < tag_val_len[0]; i++)
            {
                tag_val[i] = tag_ptr[ptr];
                ptr++;
            }

            return UFR_STATUS.UFR_OK;

        }

        //--------------------------------------------------------------------

        public static emv_tree_node_t newEmvTag(emv_tree_node_t head, byte[] input, int[] input_bytes_left, bool is_list_format, int[] status)
        {
            emv_tree_node_t p = new emv_tree_node_t(); //OVO GUBI REFERENCU I VRACA MI NULL

            int tag_index = 0;
            byte[] tag_val = new byte[1024];
            int[] tag_len = new int[1];
            int[] tag_len_len = new int[1];
            int[] tag_val_len = new int[1];
            int temp = 0;
            bool[] is_node_type = new bool[1];
            int[] tag = new int[1];
            byte temp_ptr = 0;

            status[0] = (int) parseEmvTag(input, tag, tag_val, tag_len, tag_len_len, tag_val_len);

            if (status[0] != (int) UFR_STATUS.UFR_OK)
            {
                return null;
            }

            tag_index = findEmvTagIndex(tag[0]);

            is_node_type[0] = (emv_tags[tag_index].tag_type == tag_type_t.NODE);

            temp = tag_len[0] + tag_len_len[0];

            if (!is_node_type[0] && !is_list_format)
            {
                temp += tag_val_len[0];
            }

            input_bytes_left[0] -= temp;
            temp_ptr += (byte) temp;
            Array.Copy(input, temp_ptr, input, 0, input.Length - temp_ptr);
            
            head = p;

            p.is_node_type[0] = is_node_type[0];
            p.tag[0] = tag[0];
            p.tag_bytes[0] = (byte)tag_len[0];
            p.tag_type = emv_tags[tag_index].tag_type;
            p.description = emv_tags[tag_index].description;
            p.tl_list_format = null;
            p.subnode = null;

            p.value_len = tag_val_len;

            if (!(p.is_node_type[0]) && !is_list_format && (tag_val_len[0] > 0))
            {
                if (p.tag_type == tag_type_t.STR)
                {
                    temp = tag_val_len[0] + 1;
                }

                p.value = tag_val;

                if (p.value == null)
                {
                    status[0] = (int) UFR_STATUS.SYS_ERR_OUT_OF_MEMORY;
                    return null;
                }
            }

            if (p.tag_type == tag_type_t.TL_LIST)
            {

                p.tl_list_format = newEmvTag(p.tl_list_format, p.value, p.value_len, true, status);
            }

            if ((input_bytes_left[0] < 0) || (is_node_type[0] && (input_bytes_left[0] != tag_val_len[0])))
            {
                status[0] = (int) UFR_STATUS.EMV_ERR_WRONG_INPUT_DATA;
                return null;
            }

            else if (input_bytes_left[0] > 0)
            {
                if (p.is_node_type[0])
                {
                    p.subnode = newEmvTag(p.subnode, input, input_bytes_left, false, status);
                }
                else
                {
                    p.next = newEmvTag(p.next, input, input_bytes_left, is_list_format, status);
                }

                if (status[0] != (int)UFR_STATUS.UFR_OK)
                {
                    return null;
                }

            }

            status[0] = 0;
            return head;
        }


        //--------------------------------------------------------------------
        public static int findEmvTagIndex(int tag)
        {
            int i = 0;

            do
            {
                if (emv_tags[i].tag == tag)
                    break;
                i++;
            } while (emv_tags[i].tag_id_len != 0);

            return i;
        }

        //--------------------------------------------------------------------

        public static int emvReadRecord(byte[] r_apdu, int[] Ne, byte sfi, byte record, byte[] sw)
        {
            int status; //DL_STATUS == UFR_STATUS

            sfi <<= 3;
            sfi |= 4;
            Ne[0] = 256;

            status = (int) APDUTransceive(0x00, 0xB2, record, sfi, null, 0, r_apdu, Ne, 1, sw);
            
            if (status != 0)
                return (int)UFR_STATUS.EMV_ERR_IN_CARD_READER;

            if (sw[0] == 0x6C)
            {
                Ne[0] = sw[1];

                status = (int) APDUTransceive((byte)0x00, (byte)0xB2, (byte)record, (byte)sfi, null, 0, r_apdu, Ne, (byte)1, sw);
                if (status != 0)
                {
                    return (int)UFR_STATUS.EMV_ERR_IN_CARD_READER;
                }
                else if (sw[0] == 0x8262)
                    sw[0] = (byte)0x90;

                if (sw[0] != 0x90)
                    return (int)UFR_STATUS.EMV_ERR_READING_RECORD;

            }
            
            return (int)UFR_STATUS.UFR_OK;
        }

        //--------------------------------------------------------------------

        public static int formatGetProcessingOptionsDataField(emv_tree_node_t tag_node, byte[] gpo_data_field, short[] gpo_data_field_size)
        {
            byte[] temp = new byte[1024];
            emv_tree_node_t[] pdol = new emv_tree_node_t[1];
            emv_tree_node_t p = null;
            int status;

            //gpo_data_field = null;
            gpo_data_field_size[0] = 0;

            status = getPdol(tag_node, pdol);
            if ((status > 0) && status != (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND)
                return status;

            if (status == (int)UFR_STATUS.UFR_OK && (pdol == null))
                return (int)UFR_STATUS.EMV_ERR_PDOL_IS_EMPTY;

            if (status != (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND)
            {

                p = pdol[0];
                while (p != null)
                {
                    gpo_data_field_size[0] += (short)p.value_len[0];
                    p = p.next;
                }

                if (gpo_data_field_size[0] == 0)
                    return (int)UFR_STATUS.EMV_ERR_PDOL_IS_EMPTY;
            }

            gpo_data_field_size[0] += 2;

            //gpo_data_field = new byte[gpo_data_field_size[0]];

            if (gpo_data_field == null)
            {
                gpo_data_field_size[0] = (short)0;
                return (int)UFR_STATUS.SYS_ERR_OUT_OF_MEMORY;
            }

            (gpo_data_field)[0] = (byte)0x83;
            (gpo_data_field)[1] = (byte)(gpo_data_field_size[0] - 2);

            if (status != (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND)
            {
                p = pdol[0];
                byte gpo_ptr = 2;
                //temp[0] = (byte)(gpo_data_field[gpo_ptr] + 2);

                //System.arraycopy(gpo_data_field, 2, temp, 0, gpo_data_field.length - 2);
                while (p != null)
                {
                    if (p.tag[0] == 0x9F66) // Terminal Transaction Qualifiers (TTQ) Tag
                    {
                        //temp[0] = 0x28;
                        gpo_data_field[gpo_ptr] = (byte)0x28;

                        //				temp[1] = 0x20;
                        //				temp[2] = 0xC0;
                        //				temp[3] = 0x00;
                    }
                    else if (p.tag[0] == 0x5F2A) //
                    {
                        //temp[0] = 0x09;
                        gpo_data_field[gpo_ptr] = (byte)0x09;
                        //temp[1] = 0x41;
                        gpo_data_field[gpo_ptr + 1] = (byte)0x41;
                    }
                    else if (p.tag[0] == 0x9A03)
                    {
                        //temp[0] = 0x17;
                        gpo_data_field[gpo_ptr] = (byte)0x17;
                        //temp[1] = 0x08;
                        gpo_data_field[gpo_ptr + 1] = (byte)0x08;
                        //temp[2] = 0x15;
                        gpo_data_field[gpo_ptr + 2] = (byte)0x15;
                    }

                    gpo_ptr += (byte) p.value_len[0];
                    //System.arraycopy(temp, srcPos, dest, destPos, length);
                    p = p.next;
                }

                //System.arraycopy(temp, 0, gpo_data_field, 2, temp.length - 2);
            }

            return (int)UFR_STATUS.UFR_OK;
        }
        //--------------------------------------------------------------------
        public static int getPdol(emv_tree_node_t tag_node, emv_tree_node_t[] pdol)
        {
            if (tag_node == null)
                return (int)UFR_STATUS.EMV_ERR_TAG_NOT_FOUND;

            if (tag_node.tag[0] == 0x9f38)
            {
                if (tag_node.value_len != null)
                {
                    pdol[0] = tag_node.tl_list_format;
                    return (int)UFR_STATUS.UFR_OK;
                }
                else
                {
                    return (int)UFR_STATUS.EMV_ERR_TAG_WRONG_SIZE;
                }
            }
            else
            {
                if (tag_node.subnode != null)
                {
                    return getPdol(tag_node.subnode, pdol);
                }
                else
                {
                    return getPdol(tag_node.next, pdol);
                }
            }
        }
        
        //---------------------------------------------------------------------------------------------

        public byte[] ToByteArray(String HexString)
        {

            int NumberChars = HexString.Length;
            byte[] bytes = new byte[NumberChars / 2];

            if (HexString.Length % 2 != 0)
            {
                return bytes;
            }

            for (int i = 0; i < NumberChars; i += 2)
            {
                try
                {
                    //bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
                    bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
                }
                catch (Exception e)
                {
                    //System.Windows.Forms.MessageBox.Show("Incorrect format!");
                    // ispisi gresku kao ovde
                    //System.out.println(e.getMessage());
                    break;
                }
            }

            return bytes;
        }

    };
}

