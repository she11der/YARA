import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_GRAT2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e731d563-0d16-5f84-8127-624a71f8b646"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/r3nhat/GRAT2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_guids.yar#L826-L840"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b4ac181d6bdb40eb58326c00c93ee6d6e78d7cbdb382422873d7f744ad0ec2a1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii wide
		$typelibguid0up = "5E7FCE78-1977-444F-A18E-987D708A2CFF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
