import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpgpoabuse : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ea27044f-69be-5db7-8d77-28dafb18c7e5"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_guids.yar#L2701-L2715"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e3539bb9bdf7a9986e8fcfc725233363285e1dfe3de254b6979643abfe7944a5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4f495784-b443-4838-9fa6-9149293af785" ascii wide
		$typelibguid0up = "4F495784-B443-4838-9FA6-9149293AF785" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
