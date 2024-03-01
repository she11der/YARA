rule SIGNATURE_BASE_Elmaliseker
{
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "7ecf3d5c-be91-579e-905b-5f2ad03a0e42"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7912-L7924"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
		logic_hash = "54c0b8e74a9b10fe54901c0595600af1dfc54abd3f710fc20ca87ca92236bb49"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("

	condition:
		all of them
}
