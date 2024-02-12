rule SIGNATURE_BASE_HKTL_Powerkatz_Feb19_1
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "294d6f6c-dbc8-5431-87a0-64abe582c4ea"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_aus_parl_compromise.yar#L137-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "d1d39d68c5c5a3f6142a966925e2a136e937bc09abddd4080862346683886455"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "Powerkatz32" ascii wide fullword
		$x2 = "Powerkatz64" ascii wide
		$s1 = "GetData: not found taskName" fullword ascii wide
		$s2 = "GetRes Ex:" fullword ascii wide

	condition:
		1 of ($x*) and 1 of ($s*)
}