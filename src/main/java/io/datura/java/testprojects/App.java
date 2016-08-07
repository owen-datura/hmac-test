package io.datura.java.testprojects;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class App 
{
	private static final String DATE_FORMAT = "yyyyMMddHHmmss";
	private static final String FORMATTER_TZ = "UTC";
	private static final String DELIMITER = ";";

	public static void main(String[] args) {
		String input = "walla@holla.org";
		String dateCode = "20160724002332";
		String computedHash = "529982908b5159d37d0d4334e81297ed099a1394d2ca0d950f8cfccad20d3f2e";
		crossCheckPHPHMAC(input, dateCode, computedHash);
	}

	private static void crossCheckPHPHMAC(final String input, final String formattedDate, final String computedHMAC) {
		String val = recreateInput(input, formattedDate);
		String result = createHMAC(val);
		if (result.equalsIgnoreCase(computedHMAC))
			System.out.println("It's a match! ^_^");
		else
			System.out.println("No match! :(");

		System.out.println("Pre-Computed:\t" + computedHMAC);
		System.out.println("Generated:\t" + result);
	}

	private static void generateNewHMAC(final String input) {
		String val = appendTimestamp(input);
		String result = createHMAC(val);
		System.out.println("# Input:\t" + val);
		System.out.println("# HMAC:\t" + result);
	}

	private static String recreateInput(final String input, final String date) {
		StringBuilder s = new StringBuilder();
		s.append(date);
		s.append(DELIMITER);
		s.append(input);
		return s.toString();
	}

	private static String appendTimestamp(final String input) {
		StringBuilder s = new StringBuilder();
		s.append(input);
		s.append(DELIMITER);
		s.append(getDateFormatter().format(new Date()));
		return s.toString();
	}

	private static SimpleDateFormat getDateFormatter() {
		SimpleDateFormat f = new SimpleDateFormat(DATE_FORMAT);
		f.setTimeZone(TimeZone.getTimeZone(FORMATTER_TZ));
		return f;
	}

	private static String createHMAC(String input) {
		try {
			Mac hmac = Mac.getInstance("HmacSHA256");
			SecretKeySpec keySpec = new SecretKeySpec(getPassphrase(), "HmacSHA256");
			hmac.init(keySpec);
			byte[] hashResult = hmac.doFinal(input.getBytes(StandardCharsets.UTF_8));
			return Hex.encodeHexString(hashResult);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}

	private static byte[] getPassphrase() {
		return new String("blatherskyte").getBytes(StandardCharsets.UTF_8);
	}
}
