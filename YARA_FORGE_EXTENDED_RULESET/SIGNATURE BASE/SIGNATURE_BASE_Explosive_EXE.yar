rule SIGNATURE_BASE_Explosive_EXE : APT FILE
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Check Point Software Technologies Inc."
		id = "3a9fb6b2-2f19-5d70-81ed-a08c3b8b2d80"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_volatile_cedar.yar#L1-L12"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "77eb74586f5ef2878c0d283b925e6e066f704d00525303990cf5ea7988a6637d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$DLD_S = "DLD-S:"
		$DLD_E = "DLD-E:"

	condition:
		all of them and uint16(0)==0x5A4D
}
