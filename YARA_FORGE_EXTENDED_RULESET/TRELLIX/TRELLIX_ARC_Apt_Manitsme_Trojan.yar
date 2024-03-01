rule TRELLIX_ARC_Apt_Manitsme_Trojan : TROJAN FILE
{
	meta:
		description = "Rule to detect the Manitsme trojan"
		author = "Marc Rivero | McAfee ATR Team"
		id = "49e0c934-6920-5e49-837c-27ebbbd5a1a2"
		date = "2013-03-08"
		modified = "2020-08-14"
		reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_manitsme_trojan_pdb.yar#L1-L36"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "c1c0ea096ec4d36c1312171de2a9ebe258c588528a20dbb06a7e3cf97bf1e197"
		logic_hash = "584053145249a930d3eae5e291d3553c57fa427dbecac9f04e7c0169f153b7af"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Manitsme"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "SvcMain.dll" fullword ascii
		$s2 = "rj.soft.misecure.com" fullword ascii
		$s3 = "d:\\rouji\\SvcMain.pdb" fullword ascii
		$s4 = "constructor or from DllMain." fullword ascii
		$s5 = "Open File Error" fullword ascii
		$s6 = "nRet == SOCKET_ERROR" fullword ascii
		$s7 = "Oh,shit" fullword ascii
		$s8 = "Paraing" fullword ascii
		$s9 = "Hallelujah" fullword ascii
		$s10 = "ComSpec" fullword ascii
		$s11 = "ServiceMain" fullword ascii
		$s12 = "SendTo(s,(char *)&sztop,sizeof(sztop),FILETYPE) == ERRTYPE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
