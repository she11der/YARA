rule SIGNATURE_BASE_HKTL_NET_GUID_Rubeus___FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "54638fe4-84b5-51a8-8c88-9c50ab09ff49"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/Rubeus"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_guids.yar#L1440-L1454"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b6c346bb0f6db20bd573c9a17d2b8110e6abd4fe3c51d7c717feefa2c517319b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii wide
		$typelibguid0up = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}