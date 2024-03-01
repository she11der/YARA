rule SIGNATURE_BASE_CN_Actor_RA_Tool_Ammyy_Mscorsvw : FILE
{
	meta:
		description = "Detects Ammyy remote access tool"
		author = "Florian Roth (Nextron Systems)"
		id = "71a0c5a9-b4dc-508d-a6b7-4b85b75bc34b"
		date = "2017-06-22"
		modified = "2023-12-05"
		reference = "Internal Research - CN Actor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_cn_group_btc.yar#L29-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c4b64b3aa63d80fa1a73b021bf49539af5888f53090555555c1f3fd7fbb90230"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
		hash2 = "d9ec0a1be7cd218042c54bfbc12000662b85349a6b78731a09ed336e5d3cf0b4"

	strings:
		$s1 = "Please enter password for accessing remote computer" fullword ascii
		$s2 = "Die Zugriffsanforderung wurde vom Remotecomputer abgelehnt" fullword ascii
		$s3 = "It will automatically be run the next time this computer is restart or you can start it manually" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and 3 of them )
}
