import "pe"

rule SIGNATURE_BASE_Foudre_Backdoor_Dropper_1 : FILE
{
	meta:
		description = "Detects Foudre Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "38c7d05b-d545-53c5-8db7-a7925b5b7838"
		date = "2017-08-01"
		modified = "2023-01-07"
		reference = "https://goo.gl/Nbqbt6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_foudre.yar#L31-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "77ae856e74ceb04e73c26154d7b4cf98ed0e1d8b9ac6ed78775becbff2473e13"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "6bc9f6ac2f6688ed63baa29913eaf8c64738cf19933d974d25a0c26b7d01b9ac"
		hash2 = "da228831089c56743d1fbc8ef156c672017cdf46a322d847a270b9907def53a5"

	strings:
		$x1 = "536F594A96C5496CB3949A4DA4775B576E049C57696E646F77735C43757272656E7456657273696F6E5C5C52756E" fullword wide
		$x2 = "2220263024C380B3278695851482EC32" fullword wide
		$s1 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\\\Startup\\" wide
		$s2 = "C:\\Documents and Settings\\All Users\\" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\\\Shell Folders" wide
		$s4 = "ShellExecuteW" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 4 of them ))
}
