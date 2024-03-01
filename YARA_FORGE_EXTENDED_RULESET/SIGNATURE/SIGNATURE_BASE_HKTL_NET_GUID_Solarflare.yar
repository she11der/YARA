import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Solarflare : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3645e14c-6025-59fa-a5a2-d8dacba8cd94"
		date = "2020-12-15"
		modified = "2023-04-06"
		reference = "https://github.com/mubix/solarflare"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_guids.yar#L2515-L2529"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4e35c57795ce3adaab52cba23a6d845617fed6c94dd1df048dcaa115086c513c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii wide
		$typelibguid0up = "CA60E49E-EEE9-409B-8D1A-D19F1D27B7E4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
