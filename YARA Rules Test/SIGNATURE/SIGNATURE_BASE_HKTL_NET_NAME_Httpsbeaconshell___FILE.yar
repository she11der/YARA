rule SIGNATURE_BASE_HKTL_NET_NAME_Httpsbeaconshell___FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "3bd7234b-a23e-5818-aed1-52d42023943b"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_names.yar#L327-L340"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6a0d7e1f796ae6cefa297978c743916a08b2406c37fa2c1f3f697a17cb032517"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "HTTPSBeaconShell" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}