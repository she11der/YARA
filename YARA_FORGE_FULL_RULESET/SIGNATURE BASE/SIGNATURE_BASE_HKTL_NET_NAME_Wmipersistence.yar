rule SIGNATURE_BASE_HKTL_NET_NAME_Wmipersistence : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "7a674596-c697-569d-a16c-3cefe4ff752a"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/mdsecactivebreach/WMIPersistence"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_github_net_redteam_tools_names.yar#L18-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f8f5e1b6d9b9e8e2f76a7e02385142bbeb755d1b1e41e501f4f74fcaba0a7dad"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "WMIPersistence" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
