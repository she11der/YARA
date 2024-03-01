rule SIGNATURE_BASE_Mirai_1_May17 : FILE
{
	meta:
		description = "Detects Mirai Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "ac85ee28-a01f-5c3d-a534-0c19a3dc92e7"
		date = "2017-05-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_mirai.yar#L62-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6816ab3b455bbde6c4bb43bff162615d7fc24b9d5828faa190600387c38978e1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
		hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
		hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"

	strings:
		$s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <5000KB and all of them )
}
