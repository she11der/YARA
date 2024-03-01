rule SIGNATURE_BASE_ASP_Cmdasp
{
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "e4b48843-1936-5717-b2b6-add5b4a14d04"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7390-L7403"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"
		logic_hash = "84c3148fe74b1afaa6e3bbff0aca8df1f1775759a36a673cc13d35ef7658929c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "' -- Read the output from our command and remove the temp file -- '"
		$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
		$s9 = "' -- create the COM objects that we will be using -- '"

	condition:
		all of them
}
