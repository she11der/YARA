rule TRELLIX_ARC_Cryptolocker_Rule2 : RANSOMWARE
{
	meta:
		description = "Detection of CryptoLocker Variants"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		id = "a6e808ef-4f60-5592-9440-69309784efb1"
		date = "2014-04-14"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Cryptolocker.yar#L42-L79"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "e8e03516cc0b669000c8d6b443be7a5f7a8b904abba98fd3c7d4f038de6741ab"
		score = 75
		quality = 70
		tags = "RANSOMWARE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Cryptolocker"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$string0 = "2.0.1.7" wide
		$string1 = "    <security>"
		$string2 = "Romantic"
		$string3 = "ProductVersion" wide
		$string4 = "9%9R9f9q9"
		$string5 = "IDR_VERSION1" wide
		$string6 = "button"
		$string7 = "    </security>"
		$string8 = "VFileInfo" wide
		$string9 = "LookFor" wide
		$string10 = "      </requestedPrivileges>"
		$string11 = " uiAccess"
		$string12 = "  <trustInfo xmlns"
		$string13 = "last.inf"
		$string14 = " manifestVersion"
		$string15 = "FFFF04E3" wide
		$string16 = "3,31363H3P3m3u3z3"

	condition:
		12 of ($string*)
}
