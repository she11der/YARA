import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Lime_Downloader : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "bfb0f97c-6d95-5e11-ad11-5297bcf7c3df"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_github_net_redteam_tools_guids.yar#L88-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "51e7facdbfc47f6af8f1e7408b3817e878afddb9a1bd2fbf3fabfe97746a3964"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii wide
		$typelibguid0up = "EC7AFD4C-FBC4-47C1-99AA-6EBB05094173" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
