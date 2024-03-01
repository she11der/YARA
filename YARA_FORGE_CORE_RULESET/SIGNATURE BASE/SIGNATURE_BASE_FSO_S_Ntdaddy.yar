rule SIGNATURE_BASE_FSO_S_Ntdaddy
{
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "b6b655b8-7bce-5fa5-97b7-a020a7e53f4f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8023-L8034"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
		logic_hash = "4df6f53ee9bfc0214e69dd858878026e962b90573ed48a5ffdd5523538e8f3bf"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"

	condition:
		all of them
}
