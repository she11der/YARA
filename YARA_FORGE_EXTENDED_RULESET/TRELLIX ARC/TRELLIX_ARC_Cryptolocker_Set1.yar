rule TRELLIX_ARC_Cryptolocker_Set1 : RANSOMWARE
{
	meta:
		description = "Detection of Cryptolocker Samples"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		id = "13ccc6d3-c2cc-59ac-81af-ec11fb78cd41"
		date = "2014-04-13"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Cryptolocker.yar#L1-L40"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "5be8d077537a59d860a972392be186d2697e55778f750d03b0fd3b0a73f714d9"
		score = 75
		quality = 70
		tags = "RANSOMWARE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Cryptolocker"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$string0 = "static"
		$string1 = " kscdS"
		$string2 = "Romantic"
		$string3 = "CompanyName" wide
		$string4 = "ProductVersion" wide
		$string5 = "9%9R9f9q9"
		$string6 = "IDR_VERSION1" wide
		$string7 = "  </trustInfo>"
		$string8 = "LookFor" wide
		$string9 = ":n;t;y;"
		$string10 = "        <requestedExecutionLevel level"
		$string11 = "VS_VERSION_INFO" wide
		$string12 = "2.0.1.0" wide
		$string13 = "<assembly xmlns"
		$string14 = "  <trustInfo xmlns"
		$string15 = "srtWd@@"
		$string16 = "515]5z5"
		$string17 = "C:\\lZbvnoVe.exe" wide

	condition:
		12 of ($string*)
}
