rule SIGNATURE_BASE_Shelltools_G0T_Root_Resolve
{
	meta:
		description = "Webshells Auto-generated - file resolve.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dcdb9952-63fc-57a7-ae17-ffe8ac4271f1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7925-L7942"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "69bf9aa296238610a0e05f99b5540297"
		logic_hash = "39d8ac274e94f13b5eb197be5827a95ac09df70793bd584c96b81983a565c1ce"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "3^n6B(Ed3"
		$s1 = "^uldn'Vt(x"
		$s2 = "\\= uPKfp"
		$s3 = "'r.axV<ad"
		$s4 = "p,modoi$=sr("
		$s5 = "DiamondC8S t"
		$s6 = "`lQ9fX<ZvJW"

	condition:
		all of them
}
