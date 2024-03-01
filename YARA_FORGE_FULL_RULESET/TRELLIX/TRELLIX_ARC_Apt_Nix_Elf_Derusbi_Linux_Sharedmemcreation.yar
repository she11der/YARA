rule TRELLIX_ARC_Apt_Nix_Elf_Derusbi_Linux_Sharedmemcreation : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Derusbi Linux Shared Memory creation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "8d2db62e-22fa-5bbe-ab65-f294fc911b82"
		date = "2017-05-31"
		modified = "2020-08-14"
		reference = "https://attack.mitre.org/software/S0021/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Derusbi.yar#L107-L130"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "095af979728f3b71e3192140306e4aa76011e07a25b20b0c5b3b98db41411714"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:ELF/Derusbi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

	condition:
		( uint32(0)==0x464C457F) and filesize <200KB and all of them
}
