rule SIGNATURE_BASE_HKTL_NET_NAME_Nativepayload_IP6DNS : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "3b32b408-e71a-5f2a-ae6f-72a3d6572b71"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_IP6DNS"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_names.yar#L552-L565"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "509c396b97524335735107644460eebed3146b2bc5f8dedb909c9754b2121f5f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "NativePayload_IP6DNS" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
