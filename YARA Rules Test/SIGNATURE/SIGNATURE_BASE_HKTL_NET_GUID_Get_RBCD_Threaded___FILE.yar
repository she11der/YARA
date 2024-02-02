rule SIGNATURE_BASE_HKTL_NET_GUID_Get_RBCD_Threaded___FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "fdef6dc3-da1a-5a98-a822-94e443981fdd"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/FatRodzianko/Get-RBCD-Threaded"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_guids.yar#L5384-L5398"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c771f3cf70901b6e60ec5a721e214e7c6c95169070d071caa870ca9f6235519f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e20dc2ed-6455-4101-9d78-fccac1cb7a18" ascii wide
		$typelibguid0up = "E20DC2ED-6455-4101-9D78-FCCAC1CB7A18" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}