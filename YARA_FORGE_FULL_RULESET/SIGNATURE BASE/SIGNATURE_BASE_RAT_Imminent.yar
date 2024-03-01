rule SIGNATURE_BASE_RAT_Imminent
{
	meta:
		description = "Detects Imminent RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "deddef60-c309-54e0-a488-ce937ed7eae3"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Imminent"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L359-L389"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "aebae753c119950b0b3f315c7279866caf15f4d482c0a47912c90885adcf6db2"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$v1a = "DecodeProductKey"
		$v1b = "StartHTTPFlood"
		$v1c = "CodeKey"
		$v1d = "MESSAGEBOX"
		$v1e = "GetFilezillaPasswords"
		$v1f = "DataIn"
		$v1g = "UDPzSockets"
		$v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}
		$v2a = "<URL>k__BackingField"
		$v2b = "<RunHidden>k__BackingField"
		$v2c = "DownloadAndExecute"
		$v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
		$v2e = "england.png" wide
		$v2f = "Showed Messagebox" wide

	condition:
		all of ($v1*) or all of ($v2*)
}
