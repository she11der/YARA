rule SIGNATURE_BASE_CN_Honker_Alien_Ee : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ee.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "03540f82-6662-55e3-97f8-38776271f08b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L631-L646"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "15a7211154ee7aca29529bd5c2500e0d33d7f0b3"
		logic_hash = "1f40f6c53e13aeb6b44c58f6e048a35cf3fd9fb956f26d70b3fe91bcac340ab5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "GetIIS UserName and PassWord." fullword wide
		$s2 = "Read IIS ID For FreeHost." fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
