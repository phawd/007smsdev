package com.telefoncek.zerosms.detector;

import android.telephony.SmsManager;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.ArrayList;

/**
 * Utility class for sending Type-0 SMS messages.
 * Type-0 SMS messages are true silent SMS that do not show any notification on the receiving phone.
 * The TP_PID field is set to 0x40 to indicate a Type-0 message.
 * 
 * Note: Type-0 SMS messages are completely hidden by Android since Android 2.3 (API 9).
 * They can only be detected via system log scanning with root access.
 */
public class Type0SmsSender {
    private static final String TAG = "Type0SmsSender";
    
    /**
     * Send a Type-0 SMS message to the specified phone number.
     * 
     * IMPORTANT NOTE: Android's public SmsManager API does not provide direct support
     * for sending Type-0 SMS (with TP-PID=0x40). This implementation attempts to send
     * a silent SMS that approximates Type-0 behavior using available APIs.
     * 
     * For true Type-0 SMS with TP-PID=0x40, you would need:
     * 1. Root access to use hidden Android APIs via reflection
     * 2. Custom modem AT commands (requires system privileges)
     * 3. A custom ROM with modified telephony stack
     * 
     * This implementation uses sendDataMessage which sends a binary SMS that won't
     * show a notification on most devices, providing similar (though not identical)
     * behavior to Type-0 SMS.
     * 
     * @param phoneNumber The destination phone number (international format recommended)
     * @param message Optional message content (typically empty for silent SMS)
     * @return true if the SMS was sent successfully, false otherwise
     */
    public static boolean sendType0Sms(String phoneNumber, String message) {
        try {
            SmsManager smsManager = SmsManager.getDefault();
            
            // Use sendDataMessage to send a binary SMS on port 9200
            // This creates a silent SMS that won't be displayed to the user
            // While not exactly Type-0 (TP-PID=0x40), it provides similar silent behavior
            
            // Create minimal payload
            byte[] payload = new byte[]{0x00};
            if (message != null && !message.isEmpty()) {
                payload = message.getBytes("US-ASCII");
            }
            
            // Port 9200 is commonly used for silent/binary SMS
            // The receiving app needs to register for this port to receive the message
            short destinationPort = 9200;
            
            // Send without delivery reports or status tracking
            smsManager.sendDataMessage(
                phoneNumber,           // destinationAddress
                null,                  // scAddress (use default SMSC)
                destinationPort,       // destinationPort
                payload,               // data
                null,                  // sentIntent (no confirmation)
                null                   // deliveryIntent (no delivery report)
            );
            
            Log.d(TAG, "Type-0-style SMS sent to " + phoneNumber + " on port " + destinationPort);
            Log.i(TAG, "Note: True Type-0 SMS (TP-PID=0x40) requires system-level access. " +
                       "This sends a binary SMS that provides similar silent behavior.");
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Error sending Type-0-style SMS", e);
            return false;
        }
    }
    
    /**
     * Create a Type-0 SMS PDU with TP-PID set to 0x40.
     * This is a simplified implementation that creates a basic SMS-SUBMIT PDU.
     * 
     * SMS PDU Structure (SMS-SUBMIT):
     * - SMSC Length (1 byte)
     * - SMSC Number (variable)
     * - First Octet (1 byte) - Message Type Indicator
     * - TP-MR (1 byte) - Message Reference
     * - DA-Length (1 byte) - Destination Address Length
     * - DA-Type (1 byte) - Destination Address Type
     * - Destination Number (variable)
     * - TP-PID (1 byte) - Protocol Identifier (0x40 for Type-0)
     * - TP-DCS (1 byte) - Data Coding Scheme
     * - TP-VP (1 byte) - Validity Period
     * - TP-UDL (1 byte) - User Data Length
     * - TP-UD (variable) - User Data
     * 
     * @param phoneNumber Destination phone number
     * @param message Message text (can be null or empty)
     * @return PDU byte array
     */
    private static byte[] createType0SmsPdu(String phoneNumber, String message) {
        try {
            ByteArrayOutputStream pduStream = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(pduStream);
            
            // SMSC - Leave empty (use default from SIM)
            dos.writeByte(0x00);
            
            // First Octet: SMS-SUBMIT, no validity period, no reply path, no user data header
            // 0x01 = SMS-SUBMIT
            dos.writeByte(0x01);
            
            // TP-MR (Message Reference) - can be 0 to let the network assign it
            dos.writeByte(0x00);
            
            // Destination Address (DA)
            String cleanNumber = phoneNumber.replaceAll("[^0-9+]", "");
            
            // If number starts with +, it's international format
            boolean isInternational = cleanNumber.startsWith("+");
            if (isInternational) {
                cleanNumber = cleanNumber.substring(1); // Remove the + sign
            }
            
            // DA Length (number of digits, not bytes)
            dos.writeByte(cleanNumber.length());
            
            // DA Type: 0x91 for international, 0x81 for national
            dos.writeByte(isInternational ? 0x91 : 0x81);
            
            // DA Value: Encode phone number in semi-octets (swapped nibbles)
            byte[] phoneBytes = encodeSemiOctets(cleanNumber);
            dos.write(phoneBytes);
            
            // TP-PID: Protocol Identifier
            // 0x40 = Type-0 SMS (replace short message)
            dos.writeByte(0x40);
            
            // TP-DCS: Data Coding Scheme
            // 0x00 = 7-bit default alphabet
            dos.writeByte(0x00);
            
            // TP-VP: Validity Period (if needed based on First Octet)
            // We're not using it, so we skip it
            
            // TP-UDL and TP-UD: User Data
            String textContent = (message != null && !message.isEmpty()) ? message : "";
            
            if (textContent.isEmpty()) {
                // No user data
                dos.writeByte(0x00);
            } else {
                // Encode the message in 7-bit GSM format
                byte[] userData = encode7BitGsm(textContent);
                dos.writeByte(textContent.length()); // TP-UDL: length in characters
                dos.write(userData);
            }
            
            dos.flush();
            byte[] pdu = pduStream.toByteArray();
            
            Log.d(TAG, "Created Type-0 SMS PDU: " + bytesToHex(pdu));
            
            return pdu;
            
        } catch (Exception e) {
            Log.e(TAG, "Error creating Type-0 SMS PDU", e);
            return null;
        }
    }
    
    /**
     * Encode phone number in semi-octets (swap nibbles in each byte).
     * Example: "123456" becomes 0x21 0x43 0x65
     * 
     * @param number Phone number string (digits only)
     * @return Encoded byte array
     */
    private static byte[] encodeSemiOctets(String number) {
        // Pad with F if odd length
        if (number.length() % 2 != 0) {
            number = number + "F";
        }
        
        byte[] result = new byte[number.length() / 2];
        
        for (int i = 0; i < number.length(); i += 2) {
            char c1 = number.charAt(i);
            char c2 = number.charAt(i + 1);
            
            int digit1 = (c1 == 'F') ? 0xF : Character.digit(c1, 10);
            int digit2 = (c2 == 'F') ? 0xF : Character.digit(c2, 10);
            
            // Swap nibbles: second digit in high nibble, first digit in low nibble
            result[i / 2] = (byte) ((digit2 << 4) | digit1);
        }
        
        return result;
    }
    
    /**
     * Encode text in 7-bit GSM format (simplified version).
     * This is a basic implementation that works for ASCII characters.
     * 
     * @param text Text to encode
     * @return Encoded byte array
     */
    private static byte[] encode7BitGsm(String text) {
        try {
            // For simplicity, we'll use a basic 7-bit packing
            // In production, you'd want to use proper GSM 7-bit encoding with lookup tables
            
            byte[] bytes = text.getBytes("US-ASCII");
            int len = text.length();
            byte[] result = new byte[(len * 7 + 7) / 8];
            
            int bitIndex = 0;
            for (int i = 0; i < len; i++) {
                int charValue = bytes[i] & 0x7F; // Use only 7 bits
                
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                
                // Pack 7 bits into the result array
                result[byteIndex] |= (charValue << bitOffset);
                
                if (bitOffset > 1) {
                    // Some bits overflow to next byte
                    if (byteIndex + 1 < result.length) {
                        result[byteIndex + 1] = (byte) (charValue >> (8 - bitOffset));
                    }
                }
                
                bitIndex += 7;
            }
            
            return result;
            
        } catch (Exception e) {
            Log.e(TAG, "Error encoding 7-bit GSM", e);
            return new byte[0];
        }
    }
    
    /**
     * Convert byte array to hex string for debugging.
     * 
     * @param bytes Byte array
     * @return Hex string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
