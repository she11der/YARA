rule SIGNATURE_BASE_HKTL_NET_NAME_C2Bridge : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "357051aa-61ea-5454-a996-b4e3a45ac865"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/cobbr/C2Bridge"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_names.yar#L582-L595"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d5f6d6e9d475bf2d8a49d7550bf3b718539753f3494b58462094bfc0a37b813a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "C2Bridge" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
