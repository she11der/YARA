rule BINARYALERT_Hacktool_Macos_Manwhoami_Osxchromedecrypt
{
	meta:
		description = "Decrypt Google Chrome / Chromium passwords and credit cards on macOS / OS X."
		author = "@mimeframe"
		id = "874cc999-d9c2-5017-83ec-e4be8a659476"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/manwhoami/OSXChromeDecrypt"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_manwhoami_osxchromedecrypt.yara#L1-L16"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "0974c6a5e7875e20380df0f58bf22a589b9a5c718e635ec77b42060abcf99473"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "Credit Cards for Chrome Profile" wide ascii
		$a2 = "Passwords for Chrome Profile" wide ascii
		$a3 = "Unknown Card Issuer" wide ascii
		$a4 = "ERROR getting Chrome Safe Storage Key" wide ascii
		$b1 = "select name_on_card, card_number_encrypted, expiration_month, expiration_year from credit_cards" wide ascii
		$b2 = "select username_value, password_value, origin_url, submit_element from logins" wide ascii

	condition:
		3 of ($a*) or all of ($b*)
}