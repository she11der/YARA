rule SIGNATURE_BASE_Phpspy_2005_Full
{
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		author = "Florian Roth (Nextron Systems)"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8704-L8715"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d1c69bb152645438440e6c903bac16b2"
		logic_hash = "8561161726a49374a9bc3389fef593e5d68dc437552e06736a235412183bef45"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"

	condition:
		all of them
}