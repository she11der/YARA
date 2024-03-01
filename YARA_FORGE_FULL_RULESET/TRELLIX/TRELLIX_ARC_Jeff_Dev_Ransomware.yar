rule TRELLIX_ARC_Jeff_Dev_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Jeff Dev Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "dd5e24f4-a2d8-5db5-9e7e-7f8bded5d401"
		date = "2018-08-26"
		modified = "2020-08-14"
		reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_jeff_dev.yar#L1-L28"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "386d4617046790f7f1fcf37505be4ffe51d165ba7cbd42324aed723288ca7e0a"
		logic_hash = "58a408f4e1781540e4abdb87b85b94c1f0ea49b40bf241d6d074bc2162ac2032"
		score = 75
		quality = 45
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Jeff"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "C:\\Users\\Umut\\Desktop\\takemeon" fullword wide
		$s2 = "C:\\Users\\Umut\\Desktop\\" fullword ascii
		$s3 = "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER" fullword wide
		$s4 = "WHAT YOU DO TO MY COMPUTER??!??!!!" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB) and all of them
}
