rule TRELLIX_ARC_Shrug2_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect the Shrug Ransomware"
		author = "McAfee ATR Team"
		id = "34e59296-db7c-551b-8d48-ffea20f2b4bb"
		date = "2018-07-12"
		modified = "2020-10-12"
		reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_shrug2.yar#L1-L30"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "c89833833885bafdcfa1c6ee84d7dbcf2389b85d7282a6d5747da22138bd5c59"
		logic_hash = "8c817b7fc4a0eada08b3d298c94b99a85c4e5a49a49d1c3fabdb0c6bbf56676b"
		score = 75
		quality = 20
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Shrug"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
		$s2 = "http://tempacc11vl.000webhostapp.com/" fullword wide
		$s3 = "Shortcut for @ShrugDecryptor@.exe" fullword wide
		$s4 = "C:\\Users\\" fullword wide
		$s5 = "http://clients3.google.com/generate_204" fullword wide
		$s6 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB) and all of them
}
