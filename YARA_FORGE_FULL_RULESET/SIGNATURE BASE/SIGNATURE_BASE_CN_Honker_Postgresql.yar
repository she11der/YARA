rule SIGNATURE_BASE_CN_Honker_Postgresql : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PostgreSQL.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ae90d03c-ef67-5ece-81ae-86947196a81c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L990-L1005"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
		logic_hash = "f6921e7a7c88d70c77fc30dc273aac3679a3c0ab44d4d4706d7a405f16cff6a1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "&http://192.168.16.186/details.php?id=1" fullword ascii
		$s2 = "PostgreSQL_inject" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
