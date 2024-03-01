import "pe"

rule TRELLIX_ARC_Samsamransom2016 : RANSOMWARE FILE
{
	meta:
		description = "No description has been set in the source file - Trellix ARC"
		author = "Christiaan Beek | McAfee ATR Team"
		id = "1c7985d0-d01c-52f7-8819-e038ccc01212"
		date = "2018-01-25"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_SamSam.yar#L3-L52"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "9e8034ec0ded82ad82b625d6d1b9918761decef0fd42a253722cdc620b355e1a"
		score = 75
		quality = 68
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/SamSam"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "45e00fe90c8aa8578fce2b305840e368d62578c77e352974da6b8f8bc895d75b"

	strings:
		$x1 = "Could not list processes locking resource. Failed to get size of result." fullword wide
		$s2 = "Could not list processes locking resource." fullword wide
		$s3 = "samsam.del.exe" fullword ascii
		$s4 = "samsam.exe" fullword wide
		$s5 = "RM_UNIQUE_PROCESS" fullword ascii
		$s6 = "KillProcessWithWait" fullword ascii
		$s7 = "killOpenedProcessTree" fullword ascii
		$s8 = "RM_PROCESS_INFO" fullword ascii
		$s9 = "Exception caught in process: {0}" fullword wide
		$s10 = "Could not begin restart session.  Unable to determine file locker." fullword wide
		$s11 = "samsam.Properties.Resources.resources" fullword ascii
		$s12 = "EncryptStringToBytes" fullword ascii
		$s13 = "recursivegetfiles" fullword ascii
		$s14 = "RSAEncryptBytes" fullword ascii
		$s15 = "encryptFile" fullword ascii
		$s16 = "samsam.Properties.Resources" fullword wide
		$s17 = "TSSessionId" fullword ascii
		$s18 = "Could not register resource." fullword wide
		$s19 = "<recursivegetfiles>b__0" fullword ascii
		$s20 = "create_from_resource" fullword ascii
		$op0 = { 96 00 e0 00 29 00 0b 00 34 23 }
		$op1 = { 96 00 12 04 f9 00 34 00 6c 2c }
		$op2 = { 72 a5 0a 00 70 a2 06 20 94 }

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and pe.imphash()=="f34d5f2d4577ed6d9ceec516c1f5a744" and (1 of ($x*) and 4 of them ) and all of ($op*)) or ( all of them )
}
