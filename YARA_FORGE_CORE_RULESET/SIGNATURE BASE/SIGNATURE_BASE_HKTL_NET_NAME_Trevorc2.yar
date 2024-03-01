rule SIGNATURE_BASE_HKTL_NET_NAME_Trevorc2 : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "d1634a0d-6964-5886-b836-85c3ce6b8a17"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/trustedsec/trevorc2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_names.yar#L372-L385"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c1d56ef865e6619d9d0deff90b154c63cc3036a8521d3952819e45f51fca9fea"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "trevorc2" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
