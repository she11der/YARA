rule SIGNATURE_BASE_HKTL_NET_NAME_Hexyrunner : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "67741b4d-7336-5c88-8f2c-e48c10b187b9"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/bao7uo/HexyRunner"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_github_net_redteam_tools_names.yar#L672-L685"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c55be1fe285358378a98fd1027650dd20dd8cd0aad4dc062df7a0d4538c78c3b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "HexyRunner" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
