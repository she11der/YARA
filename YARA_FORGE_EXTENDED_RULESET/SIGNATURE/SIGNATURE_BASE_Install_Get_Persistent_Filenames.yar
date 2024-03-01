import "pe"

rule SIGNATURE_BASE_Install_Get_Persistent_Filenames : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
		author = "Florian Roth (Nextron Systems)"
		id = "cf74b479-4b78-537a-878c-2f3ce004b775"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L237-L250"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "be07e3e3e96dd4676a76b32eb8fc47b2ab1f66ebbd6c2a3f1c88fc224f9f39ef"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"

	strings:
		$s1 = "Generates the persistence file name and prints it out." fullword ascii

	condition:
		( uint16(0)==0x457f and all of them )
}
