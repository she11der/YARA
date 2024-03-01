rule SIGNATURE_BASE_HKTL_NET_NAME_Shellcodetester : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "964093a4-e6d7-51b7-928a-b1cd40dc11cc"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/tophertimzen/shellcodeTester"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_github_net_redteam_tools_names.yar#L612-L625"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3101b62428eba5e36572a190bd3a11f59cf9cca10aec3cfe3000028f1b1f0a3f"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "shellcodeTester" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
