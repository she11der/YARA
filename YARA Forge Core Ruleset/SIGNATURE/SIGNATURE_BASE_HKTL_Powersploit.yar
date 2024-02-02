rule SIGNATURE_BASE_HKTL_Powersploit
{
	meta:
		description = "Detects default strings used by PowerSploit to establish persistence"
		author = "Markus Neis"
		id = "8cb0753c-c5bb-56fc-b492-4e785f4bdaf4"
		date = "2018-06-23"
		modified = "2023-12-05"
		reference = "https://www.hybrid-analysis.com/sample/16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75?environmentId=100"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_powersploit_dropper.yar#L1-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "00bc389147926f3b474a7072381bb8b9cddad3ff581a5d2182006a674e0c0163"
		score = 75
		quality = 81
		tags = ""
		hash1 = "16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75"

	strings:
		$ps = "function" nocase ascii wide
		$s1 = "/Create /RU system /SC ONLOGON" ascii wide
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

	condition:
		all of them
}