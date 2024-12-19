**Project Name: Audio DES Encryptor**

**Project Description:**

This Java project implements the Data Encryption Standard (DES) cipher algorithm for encrypting and decrypting audio files. The program prompts the user to enter the name of the audio file and a key, then uses the DES algorithm to encrypt the audio file. It also allows the user to provide the key to decrypt the ciphertext back into the original audio file. The program ensures that the encryption and decryption processes preserve the integrity of the audio data, enabling users to verify the results by playing the encrypted and decrypted audio files. 

**Key Features:**
- **Encrypt audio files** using the DES cipher algorithm.
- **Decrypt audio files** back to their original format.
- **User-friendly interface** for easy file selection and key input.
- **Compatibility with various audio file formats**.
- **Audible verification** through playback of encrypted and decrypted audio files.
- **Optional GUI application** for enhanced usability.

**Instructions:**

1. **Installation:**
   - Clone the repository to your local machine:
     ```bash
     git clone <repository-url>
     ```
   - Navigate to the project directory:
     ```bash
     cd <project-directory>
   - Compile the Java project:
     ```bash
     javac -d . *.java
     ```

2. **Usage:**
   - Run the program:
     ```bash
     java Main
     ```
   - Follow the on-screen prompts to enter the name of the audio file and the encryption key.
   - Choose whether to encrypt or decrypt the file.
   - The program will process the audio file and save the output in the appropriate format.

3. **Testing:**
   - Test the program with different audio files to ensure correct encryption and decryption.
   - Verify the integrity of the audio files by playing them after encryption and decryption.
   - Experiment with different keys to observe variations in the encrypted audio data.
