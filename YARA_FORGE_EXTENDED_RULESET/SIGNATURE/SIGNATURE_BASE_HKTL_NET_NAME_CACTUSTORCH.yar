rule SIGNATURE_BASE_HKTL_NET_NAME_CACTUSTORCH : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "7b1e3015-fada-592c-b120-20aa12247d32"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/mdsecactivebreach/CACTUSTORCH"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_names.yar#L762-L775"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "51a125a44b5d1e73509bcd29865b26f44a5ee53f6907ee9abffa3eef1bbbdea8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "CACTUSTORCH" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
