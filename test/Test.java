import java.io.File;

public class Test {

	public final static String TEMP_RES_FOLDER = "./temp/";

	static void deleteDir(File file) {
	    File[] contents = file.listFiles();
	    if (contents != null) {
	        for (File f : contents) {
	            deleteDir(f);
	        }
	    }
	    file.delete();
	}

	static void clean() {
		if( new File(TEMP_RES_FOLDER).exists()) {
			deleteDir(new File(TEMP_RES_FOLDER));
		}else {
			new File(TEMP_RES_FOLDER).mkdir();
		}
		return;
	}

	public static void main(String args[]) {

		String filename = TEMP_RES_FOLDER + "test_hello_world";

		try {
			clean();

			// Create file test
			EFS efs = new EFS(null);
			efs.username = "first_user_aaa";
			efs.password = "first_password";
			System.out.println("Creating file...");
			efs.create(filename, efs.username, efs.password);

			// Write test
			System.out.println("Writing content");
			byte[] ori_content = "Hello World!".getBytes();
			efs.write(filename, 0, ori_content, efs.password);

			// Read test
			byte[] content = efs.read(filename, 0, ori_content.length, efs.password);
			System.out.println("Read content: " + new String(content));

			// Length test
			int length = efs.length(filename, efs.password);
			System.out.println("File length: " + length);

			// FindUser test
			String username = efs.findUser(filename);
			System.out.println("File owner: " + username);

			// Integrity test
			boolean integrity = efs.check_integrity(filename, efs.password);
			System.out.println("Integrity check passed?: " + integrity);

			// Cut test
			System.out.println("Cutting file to 5 bytes");
			efs.cut(filename, 5, efs.password);

			byte[] cutContent = efs.read(filename, 0, 5, efs.password);
			System.out.println("Cut content: " + new String(cutContent));
			System.out.println("Cut file length: " + efs.length(filename, efs.password));

			// Wrong password tests
			System.out.println("TRYING ALL FUNCTIONS WITH WRONG PASSWORD");
			testWrongPassword(efs, filename);

			System.out.println("All tests completed successfully!");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	static void testWrongPassword(EFS efs, String filename) {
		try {
			efs.read(filename, 0, 1, "wrong_password");
			System.err.println("ERROR: Read worked with wrong password");
		} catch (Exception e) {
			System.out.println("Read blocked successfully");
		}

		try {
			efs.write(filename, 0, "BAD".getBytes(), "wrong_password");
			System.err.println("ERROR: Write worked with wrong password");
		} catch (Exception e) {
			System.out.println("Write blocked successfully");
		}

		try {
			efs.cut(filename, 1, "wrong_password");
			System.err.println("ERROR: Cut worked with wrong password");
		} catch (Exception e) {
			System.out.println("Cut blocked successfully");
		}

		try {
			efs.length(filename, "wrong_password");
			System.err.println("ERROR: Length returned with wrong password");
		} catch (Exception e) {
			System.out.println("Length not returned");
		}

		try {
			boolean integrity = efs.check_integrity(filename, "wrong_password");
			if(!integrity) {
				System.out.println("Integrity check blocked");
			}
			else {
				System.err.println("ERROR: Integrity check passed with wrong password");
			}	
		} catch (Exception e) {
			System.out.println("Integrity check threw exception");
		}
	}
}