rule TRELLIX_ARC_Apt_Aurora_Pdb_Samples : BACKDOOR FILE
{
	meta:
		description = "Aurora APT Malware 2006-2010"
		author = "Marc Rivero | McAfee ATR Team"
		id = "51b080b7-671b-592b-ba52-7fdd0ddf0294"
		date = "2010-01-11"
		modified = "2020-08-14"
		reference = "https://en.wikipedia.org/wiki/Operation_Aurora"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_operation_aurora.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "ce7debbcf1ca3a390083fe5753f231e632017ca041dfa662ad56095a500f2364"
		logic_hash = "5791ae7b96f2b59d0cca1ab97455bb4745edad8980ac4aff22aa36e0bc4f240e"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Aurora"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\AuroraVNC\\VedioDriver\\Release\\VedioDriver.pdb"
		$pdb1 = "\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <150KB and any of them
}
