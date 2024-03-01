rule SECUINFRA_OBFUS_Javascript_Wscript_Hex_Strings_Usage
{
	meta:
		description = "Detects the frequent usage of Wscript to get an hex encoded string from an array and interpret it. Used by e.g WSHRAT"
		author = "SECUINFRA Falcon Team"
		id = "dd55753e-4f7b-56be-a6d4-66f1d7dc8747"
		date = "2022-12-02"
		modified = "2022-02-13"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Obfuscation/javascript_obfuscation.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "62bc3261b3c2e902a82423239a7ee0bcedfccbeeeda11833b935197144dc7c35"
		score = 75
		quality = 70
		tags = ""

	strings:
		$wscript = "= WScript["
		$hex_enc_str1 = "\\x63\\x72\\x65\\x61"
		$hex_enc_str2 = "\\x73\\x63\\x72\\x69"
		$hex_enc_str3 = "\\x71\\x75\\x69\\x74"
		$hex_enc_str4 = "\\x41\\x72\\x67\\x75"

	condition:
		#wscript>30 and 2 of ($hex_enc_str*)
}
