import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpminidump : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e91e6711-d992-5a8a-97e6-1ed7847f38a4"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/b4rtik/SharpMiniDump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_guids.yar#L380-L394"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9ef422dfd066c4fff7e3e72758557bcac81883ae75f0bf0c8efc14a127e12acf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii wide
		$typelibguid0up = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
