import java.io.*;

import javax.sound.sampled.*;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JFileChooser;

import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class DES {

	public static String[] roundKeys = new String[16];
	public static String pt;
	public static String plaintext;
	public static int blockSize = 64;
	public static String keytest;
	public static String filetest;
	public static String Ciphertext;
	public static String Decrypttext;

	public static String convertDecimalToBinary(int decimal) {
		String binary = "";
		while (decimal != 0) {
			binary = (decimal % 2 == 0 ? "0" : "1") + binary;
			decimal = decimal / 2;
		}
		while (binary.length() < 4) {
			binary = "0" + binary;
		}
		return binary;
	}

	public static int convertBinaryToDecimal(S
			tring binary) {
		int decimal = 0;
		int counter = 0;
		int size = binary.length();
		for (int i = size - 1; i >= 0; i--) {
			if (binary.charAt(i) == '1') {
				decimal += Math.pow(2, counter);
			}
			counter++;
		}
		return decimal;
	}

	public static String shiftLeftOnce(String keyChunk) {
		String shifted = "";
		for (int i = 1; i < 28; i++) {
			shifted += keyChunk.charAt(i);
		}
		shifted += keyChunk.charAt(0);
		return shifted;
	}

	public static String shiftLeftTwice(String keyChunk) {
		String shifted = "";
		for (int i = 0; i < 2; i++) {
			for (int j = 1; j < 28; j++) {
				shifted += keyChunk.charAt(j);
			}
			shifted += keyChunk.charAt(0);
			keyChunk = shifted;
			shifted = "";
		}
		return keyChunk;
	}

	public static String xor(String a, String b) {
		String result = "";
		int size = b.length();
		for (int i = 0; i < size; i++) {
			if (a.charAt(i) != b.charAt(i)) {
				result += "1";
			} else {
				result += "0";
			}
		}
		return result;
	}

	public static void generateKeys(String key) {
		// The PC1 table
		int[] pc1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
				52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5,
				28, 20, 12, 4 };
		// The PC2 table
		int[] pc2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
				31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
		// 1. Compressing the key using the PC1 table
		String permKey = "";
		for (int i = 0; i < 56; i++) {
			permKey += key.charAt(pc1[i] - 1);
		}
		// 2. Dividing the key into two equal halves
		String left = permKey.substring(0, 28);
		String right = permKey.substring(28, 56);
		for (int i = 0; i < 16; i++) {
			// 3.1. For rounds 1, 2, 9, 16 the key_chunks
			// are shifted by one.
			if (i == 0 || i == 1 || i == 8 || i == 15) {
				left = shiftLeftOnce(left);
				right = shiftLeftOnce(right);
			}
			// 3.2. For other rounds, the key_chunks
			// are shifted by two
			else {
				left = shiftLeftTwice(left);
				right = shiftLeftTwice(right);
			}
			// Combining the two chunks
			String combinedKey = left + right;
			String roundKey = "";
			// Finally, using the PC2 table to transpose the key bits
			for (int j = 0; j < 48; j++) {
				roundKey += combinedKey.charAt(pc2[j] - 1);
			}
			roundKeys[i] = roundKey;
		}
	}

	public static String DES(String plainText) {
		int[] initial_permutation = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30,
				22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

		int[] expansion_table = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16,
				17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

		int[][][] substitution_boxes = {
				{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
						{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
						{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
						{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
				{ { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
						{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
						{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
						{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
				{ { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
						{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
						{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
						{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
				{ { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
						{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
						{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
						{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
				{ { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
						{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
						{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
						{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
				{ { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
						{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
						{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
						{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
				{ { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
						{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
						{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
						{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
				{ { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
						{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
						{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
						{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } };

		int[] permutationTable = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3,
				9, 19, 13, 30, 6, 22, 11, 4, 25 };

		int[] inverse_permutation = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54,
				22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
				34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

		String perm = "";
		for (int i = 0; i < 64; i++) {
			perm += plainText.charAt(initial_permutation[i] - 1);
		}

		// 2. Dividing the result into two equal halves
		String left = perm.substring(0, 32);
		String right = perm.substring(32, 64);

		for (int i = 0; i < 16; i++) {
			String right_expanded = "";
			// 3.1. The right half of the plain text is expanded
			for (int j = 0; j < 48; j++) {
				right_expanded += right.charAt(expansion_table[j] - 1);
			}

			// 3.3. The result is xored with a key
			String xored = xor(roundKeys[i], right_expanded);
			String res = "";
			// 3.4. The result is divided into 8 equal parts and passed
			// through 8 substitution boxes. After passing through a
			// substitution box, each box is reduced from 6 to 4 bits.
			for (int j = 0; j < 8; j++) {
				// Finding row and column indices to lookup the
				// substitution box
				String row1 = xored.substring(j * 6, j * 6 + 1) + xored.substring(j * 6 + 5, j * 6 + 6);
				int row = convertBinaryToDecimal(row1);
				String col1 = xored.substring(j * 6 + 1, j * 6 + 2) + xored.substring(j * 6 + 2, j * 6 + 3)
						+ xored.substring(j * 6 + 3, j * 6 + 4) + xored.substring(j * 6 + 4, j * 6 + 5);
				int col = convertBinaryToDecimal(col1);
				int val = substitution_boxes[j][row][col];
				res += convertDecimalToBinary(val);
			}
			// 3.5. Another permutation is applied
			String perm2 = "";
			for (int j = 0; j < 32; j++) {
				perm2 += res.charAt(permutationTable[j] - 1);
			}
			// 3.6. The result is xored with the left half
			xored = xor(perm2, left);
			// 3.7. The left and the right parts of the plain text are swapped
			left = xored;
			if (i < 15) {
				String temp = right;
				right = xored;
				left = temp;
			}
		}
		String combined_text = left + right;
		String ciphertext = "";
		// The inverse of the initial permutation is applied
		for (int i = 0; i < 64; i++) {
			ciphertext += combined_text.charAt(inverse_permutation[i] - 1);
		}
		// And we finally get the cipher text
		return ciphertext;

	}

	public static String[] divideIntoBlocks(String input) {
		int numBlocks = (int) Math.ceil((double) input.length() / blockSize);
		String[] blocks = new String[numBlocks];

		for (int i = 0; i < numBlocks; i++) {
			int startIndex = i * blockSize;
			int endIndex = Math.min((i + 1) * blockSize, input.length());
			String block = input.substring(startIndex, endIndex);

			// Complete the block with zeros if it is shorter than 64 bits
			if (block.length() < blockSize) {
				block = String.format("%-" + blockSize + "s", block).replace(' ', '0');
			}

			blocks[i] = block;
		}

		return blocks;
	}

	public static String convertAudioToBinary(String audioFilePath) {
		File audioFile = new File(audioFilePath);
		byte[] audioData = new byte[(int) audioFile.length()];

		try {
			AudioInputStream audioStream = AudioSystem.getAudioInputStream(audioFile);
			audioStream.read(audioData);
		} catch (UnsupportedAudioFileException | IOException e) {
			e.printStackTrace();
		}

		StringBuilder binaryData = new StringBuilder();
		for (byte b : audioData) {
			binaryData.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
		}

		return binaryData.toString();
	}

	public static void convertBinaryToAudioEncrypt(String binaryData, AudioFormat format) {
		String outputFilePath = "C:\\encryptfile.wav";
		byte[] audioData = new byte[binaryData.length() / 8];

		for (int i = 0; i < binaryData.length(); i += 8) {
			String byteString = binaryData.substring(i, i + 8);
			byte byteValue = (byte) Integer.parseInt(byteString, 2);
			audioData[i / 8] = byteValue;
		}

		try {
			AudioInputStream audioStream = new AudioInputStream(new ByteArrayInputStream(audioData), format,
					audioData.length / format.getFrameSize());
			AudioSystem.write(audioStream, AudioFileFormat.Type.WAVE, new File(outputFilePath));

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void convertBinaryToAudioDecrypt(String binaryData, AudioFormat format) {
		String outputFilePath = "C:\\dcryptfile.wav";
		byte[] audioData = new byte[binaryData.length() / 8];

		for (int i = 0; i < binaryData.length(); i += 8) {
			String byteString = binaryData.substring(i, i + 8);
			byte byteValue = (byte) Integer.parseInt(byteString, 2);
			audioData[i / 8] = byteValue;
		}

		try {
			AudioInputStream audioStream = new AudioInputStream(new ByteArrayInputStream(audioData), format,
					audioData.length / format.getFrameSize());
			AudioSystem.write(audioStream, AudioFileFormat.Type.WAVE, new File(outputFilePath));

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static String textToBinary(String text) {
		StringBuilder binaryStringBuilder = new StringBuilder();
		for (char c : text.toCharArray()) {
			String binaryChar = String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0');
			binaryStringBuilder.append(binaryChar);
		}
		return binaryStringBuilder.toString();
	}

	public static void main(String[] args) {

		GUI();

	}

	public static void GUI() {

		JFrame frame = new JFrame("DES Algorithm");
		frame.setSize(350, 250);
		frame.setLayout(null);

		JLabel label = new JLabel("Enter Key:");
		label.setBounds(70, 10, 300, 30);

		JTextField textField = new JTextField();
		textField.setBounds(70, 35, 200, 30);

		JButton button = new JButton("Choose WAV File");
		button.setBounds(90, 100, 150, 30);

		JLabel label2 = new JLabel();
		label2.setBounds(80, 70, 300, 30);

		button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
				fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("WAV files", "wav"));

				int returnValue = fileChooser.showOpenDialog(null);

				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fileChooser.getSelectedFile();
					String filePath = selectedFile.getAbsolutePath();
					if (filePath.toLowerCase().endsWith(".wav")) {
						label2.setText("Selected File: " + filePath);
						filetest = filePath;
					} else {
						label2.setText("Please select a .wav file");
					}
				} else {
					label2.setText("No file selected");
				}
			}
		});

		JLabel errorLabel = new JLabel();
		errorLabel.setBounds(113, 170, 300, 30);

		JButton saveButton = new JButton("Start DES");
		saveButton.setBounds(115, 150, 100, 30);
		saveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String key = textField.getText();
				if (!key.isEmpty()) {
					String keytext = key; // Saving the key in keytext variable
					keytest = keytext;
					try {
						frame.dispose();
						processFile();

					} catch (IOException | UnsupportedAudioFileException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} else {
					errorLabel.setText("Please enter a key");
				}
			}
		});

		frame.add(textField);
		frame.add(label);
		frame.add(label2);
		frame.add(button);
		frame.add(saveButton);
		frame.add(errorLabel);
		frame.setLocationRelativeTo(null);
		frame.setVisible(true);

	}

	public static void frameDisplay() {
	    JFrame frame2 = new JFrame("Audio");
	    frame2.setSize(300, 200);
	    frame2.setLayout(null);
	    JLabel label = new JLabel("Play Audio Before Encryption");
	    label.setBounds(10, 0, 300, 50); // Adjusted position and size of the label
	    JButton playButton1 = new JButton("Play");
	    playButton1.setBounds(200, 10, 80, 30);
	    frame2.add(playButton1);
	    frame2.add(label);
	    playButton1.addActionListener(new ActionListener() {
	        @Override
	        public void actionPerformed(ActionEvent e) {
	            // Code to play the audio
	        	try {
	                File audioFile = new File(filetest); // Replace with the actual path to your audio file
	                AudioInputStream audioStream = AudioSystem.getAudioInputStream(audioFile);
	                
	                Clip clip = AudioSystem.getClip();
	                clip.open(audioStream);
	                clip.start();
	            } catch (Exception ex) {
	                System.out.println("Something Wrong!");
	            }
	        }
	    });
	    JLabel label1 = new JLabel("Play Audio After Encryption");
	    label1.setBounds(10, 50, 300, 50); // Adjusted position and size of the label
	    JButton playButton2 = new JButton("Play");
	    playButton2.setBounds(200, 60, 80, 30);
	    frame2.add(playButton2);
	    frame2.add(label1);
	    playButton2.addActionListener(new ActionListener() {
	        @Override
	        public void actionPerformed(ActionEvent e) {
	            // Code to play the audio
	        	try {
	                File audioFile = new File("C:\\encryptfile.wav"); // Replace with the actual path to your audio file
	                AudioInputStream audioStream = AudioSystem.getAudioInputStream(audioFile);
	                
	                Clip clip = AudioSystem.getClip();
	                clip.open(audioStream);
	                clip.start();
	            } catch (Exception ex) {
	                System.out.println("Something Wrong!");
	            }
	        }
	    });
	    JLabel label2 = new JLabel("Play Audio After Decryption");
	    label2.setBounds(10, 100, 300, 50); // Adjusted position and size of the label
	    JButton playButton3 = new JButton("Play");
	    playButton3.setBounds(200, 110, 80, 30);
	    frame2.add(playButton3);
	    frame2.add(label2);
	    playButton3.addActionListener(new ActionListener() {
	        @Override
	        public void actionPerformed(ActionEvent e) {
	            // Code to play the audio
	        	try {
	                File audioFile = new File("C:\\dcryptfile.wav"); // Replace with the actual path to your audio file
	                AudioInputStream audioStream = AudioSystem.getAudioInputStream(audioFile);
	                
	                Clip clip = AudioSystem.getClip();
	                clip.open(audioStream);
	                clip.start();
	            } catch (Exception ex) {
	                System.out.println("Something Wrong!");
	            }
	        }
	    });
	    frame2.setLocationRelativeTo(null);
	    frame2.setVisible(true);
	}



	public static String getBiggestParagraph(String... paragraphs) {
		String biggestParagraph = "";
		int maxParagraphLength = 0;

		for (String paragraph : paragraphs) {
			if (paragraph.length() > maxParagraphLength) {
				biggestParagraph = paragraph;
				maxParagraphLength = paragraph.length();
			}
		}

		return biggestParagraph;
	}

	public static void processFile() throws IOException, UnsupportedAudioFileException {

		AudioInputStream stream = AudioSystem.getAudioInputStream(new File(filetest));
		AudioFormat format = stream.getFormat();

		String binaryData = convertAudioToBinary(filetest);

		// binary of the audio
		plaintext = binaryData;
		System.out.println("plaintext: "+plaintext);
		
		
		String[] encryptedDataBlocks = divideIntoBlocks(binaryData);

		String inputText = keytest;
		String key = textToBinary(inputText);
		if (key.length() < 64) {
			key = completeWithZeros(key, 64);
		}
		generateKeys(key);

		String encryptedText = "";
		for (int i = 0; i < encryptedDataBlocks.length; i++) {
			encryptedText += DES(encryptedDataBlocks[i]);
		}
		Ciphertext = encryptedText;
		System.out.println("Finish Encryption!");
		System.out.println("Ciphertext: "+ Ciphertext);

		String[] decryptedDataBlocks = divideIntoBlocks(encryptedText);

		int i = 15;
		int j = 0;
		while (i > j) {
			String temp = roundKeys[i];
			roundKeys[i] = roundKeys[j];
			roundKeys[j] = temp;
			i--;
			j++;
		}
		convertBinaryToAudioEncrypt(encryptedText, format);

		String decryptedText = "";
		for (i = 0; i < decryptedDataBlocks.length; i++) {
			decryptedText += DES(decryptedDataBlocks[i]);
		}
		Decrypttext = decryptedText;
		System.out.println("Finish Decryption!");
		System.out.println("Decryptiontext: "+ Decrypttext);

		convertBinaryToAudioDecrypt(decryptedText, format);

		frameDisplay();

	}

	public static String completeWithZeros(String binary, int targetLength) {
		StringBuilder paddedBinary = new StringBuilder(binary);
		while (paddedBinary.length() < targetLength) {
			paddedBinary.insert(0, "0"); // Insert zeros at the beginning
		}
		return paddedBinary.toString();
	}

}