import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Dotnetavbypass_Master : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4004271b-4fbe-58bb-9613-a077e76324b3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/lockfale/DotNetAVBypass-Master"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_guids.yar#L1342-L1356"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "28446fae71b06f0418a5dd3cb6d6842dcc930313f7740704770b41f16ad0e7b5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii wide
		$typelibguid0up = "4854C8DC-82B0-4162-86E0-A5BBCBC10240" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
