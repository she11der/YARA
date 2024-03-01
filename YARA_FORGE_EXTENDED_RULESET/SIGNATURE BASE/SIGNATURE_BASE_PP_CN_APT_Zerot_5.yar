rule SIGNATURE_BASE_PP_CN_APT_Zerot_5 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "2a7c6a36-aace-562e-bbc4-425c1d93fab1"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L77-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fbc1a2e078cfae7a9c72612b9c769e84d8c1d59c89e05001571ad00071e38577"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "74dd52aeac83cc01c348528a9bcb20bbc34622b156f40654153e41817083ba1d"

	strings:
		$x1 = "dbozcb" fullword ascii
		$s1 = "nflogger.dll" fullword ascii
		$s2 = "/svchost.exe" fullword ascii
		$s3 = "1207.htm" fullword ascii
		$s4 = "/1207.htm" fullword ascii

	condition:
		( uint16(0)==0x5449 and filesize <1000KB and 1 of ($x*) and 1 of ($s*)) or ( all of them )
}
