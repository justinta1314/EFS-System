
/**
 * @author Justin Ta
 * @netid JXT220064
 * @email jxt220064@utdallas.edu
 */

import java.io.File;
public class EFS extends Utility{

    private static class AuthInfo {
        int fileLength;
        byte[] encryptionKey;
        byte[] macKey;
        byte[] iv;

        AuthInfo(int len, byte[] e, byte[] m, byte[] i) {
            fileLength = len;
            encryptionKey = e;
            macKey = m;
            iv = i;
        }
    }
    /* Helper Functions */


    private AuthInfo verifyPassword(String file_name, String password) throws Exception {
        File root = new File(file_name);
        File metaFile = new File(root, "0");
        byte[] metadata = read_from_file(metaFile);

        byte[] salt = new byte[16];
        System.arraycopy(metadata, 0, salt, 0, 16);

        int iterations = 
            ((metadata[16] & 0xFF) << 24) | 
            ((metadata[17] & 0xFF) << 16) | 
            ((metadata[18] & 0xFF) << 8) | 
            (metadata[19] & 0xFF);
        byte[] iv = new byte[16];
        System.arraycopy(metadata, 149, iv, 0, 16);

        byte[] encryptedSecret = new byte[843];
        System.arraycopy(metadata, 165, encryptedSecret, 0, 843);

        byte[] storedTag = new byte[16];
        System.arraycopy(metadata, 1008, storedTag, 0, 16);

        // derive keys
        byte[] masterKey = deriveKeys(password, salt, iterations);
        byte[] encryptionKey = hash_SHA256(concat(masterKey, "ENC".getBytes("ASCII")));
        byte[] macKey = hash_SHA256(concat(masterKey, "MAC".getBytes("ASCII")));

        // decrypt secret metadata
        byte[] secret = AES_CTR(encryptedSecret, encryptionKey, iv);

        // verify password
        byte[] storedPwCheck = new byte[32];
        System.arraycopy(secret, 4, storedPwCheck, 0, 32);

        byte[] computedPwCheck = hash_SHA256(masterKey);

        for(int i = 0; i < 32; i++) {
            if(computedPwCheck[i] != storedPwCheck[i]) {
                throw new PasswordIncorrectException();
            }
        }

        // verify metadata integrity
        byte[] tagInput = new byte[1008];
        System.arraycopy(metadata, 0, tagInput, 0, 1008);

        byte[] computedTag = hash_SHA256(concat(macKey, tagInput));

        for(int i = 0; i < 16; i++) {
            if(computedTag[i] != storedTag[i]) {
                throw new Exception("Metadata corrupted");
            }
        }

        // get file length
        int fileLength = 
            ((secret[0] & 0xFF) << 24) | 
            ((secret[1] & 0xFF) << 16) | 
            ((secret[2] & 0xFF) << 8) | 
            (secret[3] & 0xFF);

        return new AuthInfo(fileLength, encryptionKey, macKey, iv);
    }

    private byte[] intToBytes(int x) {
        byte[] b = new byte[4];
        b[0] = (byte)(x >> 24);
        b[1] = (byte)(x >> 16);
        b[2] = (byte)(x >> 8);
        b[3] = (byte)(x);
        return b;
    }

    private byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length;
        }
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, currentIndex, arr.length);
            currentIndex += arr.length;
        }
        return result;
    }

    private byte[] deriveKeys(String password, byte[] salt, int iterations) throws Exception {
        byte[] key = concat(password.getBytes("ASCII"), salt);
        for (int i = 0; i < iterations; i++) {
            key = hash_SHA256(key);
        }
        return key;
    }

    private void increment(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                break;
            }
        }
    }

    private byte[] AES_CTR(byte[] data, byte[] key, byte[] iv) throws Exception {
        byte[] output = new byte[data.length];
        byte[] counter = iv.clone();
        for (int i = 0; i < data.length; i += 16) {
            byte[] stream = encrypt_AES(counter, key);

            for(int j = 0; j < 16 && i + j < data.length; j++) {
                output[i + j] = (byte)(data[i + j] ^ stream[j]);
            }
            increment(counter);
        }
        return output;
    }

    private byte[] blockIV(byte[] baseIV, int blockNum) {
        byte[] iv = baseIV.clone();
        for (int i = 15; i >= 0 && blockNum > 0; i--) {
            int sum = (iv[i] & 0xFF) + (blockNum & 0xFF);
            iv[i] = (byte)sum;
            blockNum = sum >> 8;
        }
        return iv;
    }

    private void debug(Exception e, String location) {
        System.err.println("\nEFS Error at " + location ) ;
        System.err.println("Message: " + e.getMessage());
        e.printStackTrace();
    }

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        try {
            // make directory
            File root = new File(file_name);
            if (root.exists()) {
                return;
            }
            if(!root.mkdirs()) {
                throw new Exception("Failed to create file directory: " + root.getAbsolutePath());
            }

            byte[] salt = secureRandomNumber(16);
            byte[] iv = secureRandomNumber(16);
            int iterations = 100000;

            // derive master key
            byte[] masterKey = deriveKeys(password, salt, iterations);

            // split master key into encryption key and mac key
            byte[] encryptionKey = hash_SHA256(concat(masterKey, "ENC".getBytes("ASCII")));
            byte[] macKey = hash_SHA256(concat(masterKey, "MAC".getBytes("ASCII")));

            /* Build secret metadata */
            byte[] secret = new byte[843];

            // file length = 0 initially
            System.arraycopy(intToBytes(0), 0, secret, 0, 4);

            // password check value
            byte[] pwcheck = hash_SHA256(masterKey);
            System.arraycopy(pwcheck, 0, secret, 4, 32);

            // add padding
            byte[] padding = secureRandomNumber(807);
            System.arraycopy(padding, 0, secret, 36, 807);

            /* Encrypt secret metadata */
            byte[] encryptedSecret = AES_CTR(secret, encryptionKey, iv);

            /* Build metadata */
            byte[] metadata = new byte[1024];
            int pos = 0;

            // salt
            System.arraycopy(salt, 0, metadata, pos, 16);
            pos += 16;

            // iteration count
            System.arraycopy(intToBytes(iterations), 0, metadata, pos, 4);
            pos += 4;

            // username length
            metadata[pos++] = (byte)user_name.length();

            // username padded to 128 bytes
            byte[] uname = new byte[128];
            byte[] ubytes = user_name.getBytes("ASCII");
            System.arraycopy(ubytes, 0, uname, 0, ubytes.length);
            System.arraycopy(uname, 0, metadata, pos, 128);
            pos += 128;

            // IV
            System.arraycopy(iv, 0, metadata, pos, 16);
            pos += 16;

            // Encrypted secret metadata
            System.arraycopy(encryptedSecret, 0, metadata, pos, 843);
            pos += 843;

            // metadata HMAC
            byte[] tag = hash_SHA256(concat(macKey, java.util.Arrays.copyOfRange(metadata, 0, pos)));
            System.arraycopy(tag, 0, metadata, pos, 16);

            /* Save metadata block */
            File metaFile = new File(root, "0");
            save_to_file(metadata, metaFile);

            /* Create initial empty data block */
            File firstDataBlock = new File(root, "1");
            byte[] emptyBlock = new byte[1024]; // initialized to zeros
            byte[] encryptedBlock = AES_CTR(emptyBlock, encryptionKey, blockIV(iv, 0));
            save_to_file(encryptedBlock, firstDataBlock);
            
        } catch (Exception e) {
            debug(e, "create()");
        }
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
    	File root = new File(file_name);
        File metaFile = new File(root, "0");
        byte[] metadata = read_from_file(metaFile);

        int usernameLength = metadata[20] & 0xFF; // unsigned byte

        byte[] usernameBytes = new byte[usernameLength];
        System.arraycopy(metadata, 21, usernameBytes, 0, usernameLength);

        return new String(usernameBytes, "ASCII");
    }

    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {
    	AuthInfo auth = verifyPassword(file_name, password);
        return auth.fileLength;
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {

        AuthInfo auth = verifyPassword(file_name, password);

        if(starting_position < 0 || len < 0 ||
        starting_position + len > auth.fileLength) {
            throw new Exception("Invalid read range");
        }

        File root = new File(file_name);

        byte[] result = new byte[len];
        int bytesRead = 0;
        int pos = starting_position;

        while(bytesRead < len) {

            int blockNum = pos / 1024;
            int blockOffset = pos % 1024;

            File blockFile = new File(root, Integer.toString(blockNum + 1));

            byte[] encryptedBlock = read_from_file(blockFile);

            byte[] iv = blockIV(auth.iv, blockNum);

            byte[] decryptedBlock = AES_CTR(encryptedBlock, auth.encryptionKey, iv);

            int bytesToCopy = Math.min(1024 - blockOffset, len - bytesRead);

            System.arraycopy(decryptedBlock, blockOffset, result, bytesRead, bytesToCopy);

            bytesRead += bytesToCopy;
            pos += bytesToCopy;
        }

        return result;
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {

        AuthInfo auth = verifyPassword(file_name, password);

        if(content.length == 0){
            return;
        } 

        if(starting_position < 0) {
            throw new Exception("Invalid write range");
        }

        int newFileLength = Math.max(auth.fileLength, starting_position + content.length);

        File root = new File(file_name);

        int blockSize = 1024;

        int startBlock = starting_position / blockSize;
        int endBlock = (starting_position + content.length - 1) / blockSize;

        int dataOffset = 0;

        for(int blockNum = startBlock; blockNum <= endBlock; blockNum++) {

            File dataFile = new File(root, Integer.toString(blockNum + 1));

            byte[] block = dataFile.exists() ? read_from_file(dataFile) : new byte[blockSize];

            byte[] iv = blockIV(auth.iv, blockNum);

            byte[] decryptedBlock = AES_CTR(block, auth.encryptionKey, iv);

            int blockStart = (blockNum == startBlock) ? starting_position % blockSize : 0;

            int blockEnd = (blockNum == endBlock) ? (starting_position + content.length) % blockSize : blockSize;

            if(blockEnd == 0) {
                blockEnd = blockSize;
            }
            int bytesToWrite = blockEnd - blockStart;

            System.arraycopy(content, dataOffset, decryptedBlock, blockStart, bytesToWrite);

            dataOffset += bytesToWrite;

            byte[] encryptedBlock = AES_CTR(decryptedBlock, auth.encryptionKey, iv);

            save_to_file(encryptedBlock, dataFile);
        }

        // update metadata

        auth.fileLength = newFileLength;

        File metaFile = new File(root, "0");
        byte[] metadata = read_from_file(metaFile);

        byte[] encryptedSecret = new byte[843];
        System.arraycopy(metadata, 165, encryptedSecret, 0, 843);

        byte[] secret = AES_CTR(encryptedSecret, auth.encryptionKey, auth.iv);

        System.arraycopy(intToBytes(auth.fileLength), 0, secret, 0, 4);

        byte[] newEncryptedSecret = AES_CTR(secret, auth.encryptionKey, auth.iv);

        System.arraycopy(newEncryptedSecret, 0,metadata, 165, 843);

        byte[] tagInput = new byte[1008];
        System.arraycopy(metadata, 0, tagInput, 0, 1008);

        byte[] newTag = hash_SHA256(concat(auth.macKey, tagInput));

        System.arraycopy(newTag, 0, metadata, 1008, 16);

        save_to_file(metadata, metaFile);
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        try {
            AuthInfo auth = verifyPassword(file_name, password);
            File root = new File(file_name);
            int blockSize = 1024;

            int numBlocks = (auth.fileLength == 0) ? 0 : ((auth.fileLength - 1) / blockSize) + 1;

            for(int blockNum = 0; blockNum < numBlocks; blockNum++) {
                File dataFile = new File(root, Integer.toString(blockNum + 1));
                if(!dataFile.exists()) {
                    return false; // missing block
                }

                byte[] encrypted = read_from_file(dataFile);

                if(encrypted.length != blockSize) {
                    return false; // invalid block size
                }

                byte[] iv = blockIV(auth.iv, blockNum);
                AES_CTR(encrypted, auth.encryptionKey, iv); // will throw if decryption fails
            }

            int blockIndex = numBlocks + 1;

            while (true) { 
                File extra = new File(root, Integer.toString(blockIndex));

                if(!extra.exists()) {
                    break;
                }

                return false; // unexpected extra block
            }
            return true;

        } catch (PasswordIncorrectException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {

        AuthInfo auth = verifyPassword(file_name, password);

        if(length < 0 || length > auth.fileLength) {
            throw new Exception("Invalid cut length");
        }
        
        File root = new File(file_name);
        int blockSize = 1024;

        int numBlocks = (length == 0) ? 0 : ((length - 1) / blockSize) + 1;

        int oldNumBlocks = (auth.fileLength == 0) ? 0 : ((auth.fileLength - 1) / blockSize) + 1;

        /* delete extra blocks */
        for(int b = numBlocks; b < oldNumBlocks; b++) {
            File f = new File(root, Integer.toString(b+1));
            
            if(f.exists()) {
                f.delete();
            } 
        }

        /* fix last block padding */
        if(numBlocks > 0) {

            int last = numBlocks-1;

            File lastBlock = new File(root,Integer.toString(last+1));

            byte[] block = lastBlock.exists() ? read_from_file(lastBlock) : new byte[blockSize];

            byte[] iv = blockIV(auth.iv, last);

            byte[] decrypted = AES_CTR(block, auth.encryptionKey, iv);

            int used = length % blockSize;

            if(used < blockSize) {
                byte[] padding = secureRandomNumber(blockSize-used);

                System.arraycopy(padding, 0, decrypted, used, blockSize-used);
            }

            byte[] encrypted = AES_CTR(decrypted, auth.encryptionKey, iv);

            save_to_file(encrypted, lastBlock);
        }

        /* update metadata */

        File metaFile=new File(root,"0");
        byte[] metadata=read_from_file(metaFile);

        byte[] encryptedSecret=new byte[843];
        System.arraycopy(metadata,165,encryptedSecret,0,843);

        byte[] secret=
            AES_CTR(encryptedSecret,
                    auth.encryptionKey,
                    auth.iv);

        System.arraycopy(intToBytes(length),
                        0,secret,0,4);

        byte[] newEncryptedSecret=
            AES_CTR(secret,auth.encryptionKey,auth.iv);

        System.arraycopy(newEncryptedSecret,0,metadata,165,843);

        byte[] tagInput=new byte[1008];
        System.arraycopy(metadata,0,tagInput,0,1008);

        byte[] newTag=
            hash_SHA256(concat(auth.macKey,tagInput));

        System.arraycopy(newTag,0,metadata,1008,16);

        save_to_file(metadata,metaFile);

        auth.fileLength = length;
    }
}
