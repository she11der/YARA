rule SIGNATURE_BASE_PP_CN_APT_Zerot_3 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "99aa29cf-d962-5a3d-bd28-6486c40822bb"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L41-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6920febf177667610e3edb8ba88ec137d085a867c1d6a570d4785fcc9cc62d49"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ee2e2937128dac91a11e9bf55babc1a8387eb16cebe676142c885b2fc18669b2"

	strings:
		$s1 = "/svchost.exe" fullword ascii
		$s2 = "RasTls.dll" fullword ascii
		$s3 = "20160620.htm" fullword ascii
		$s4 = "* $l&$" fullword ascii
		$s5 = "dfjhmh" fullword ascii
		$s6 = "/20160620.htm" fullword ascii

	condition:
		( uint16(0)==0x5449 and filesize <1000KB and 3 of them ) or ( all of them )
}
