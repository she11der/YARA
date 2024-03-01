rule SIGNATURE_BASE_VBS_Dropper_Script_Dec17_1 : FILE
{
	meta:
		description = "Detects a supicious VBS script that drops an executable"
		author = "Florian Roth (Nextron Systems)"
		id = "60f23d32-0737-501f-bf1c-1ca32af62efc"
		date = "2018-01-01"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_suspicious_strings.yar#L88-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f3c55bd6bf382891263887e46a794329c78bff87b7685088911261fc3b3b133d"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "TVpTAQEAAAAEAA"
		$s2 = "TVoAAAAAAAAAAA"
		$s3 = "TVqAAAEAAAAEAB"
		$s4 = "TVpQAAIAAAAEAA"
		$s5 = "TVqQAAMAAAAEAA"
		$a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii

	condition:
		filesize <600KB and $a1 and 1 of ($s*)
}
