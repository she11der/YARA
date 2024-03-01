rule SIGNATURE_BASE_RAT_Hawkeye
{
	meta:
		description = "Detects HawkEye RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "22b1d1e6-feea-5f84-9564-326ad80bbd8d"
		date = "2015-01-06"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/HawkEye"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L333-L357"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "db3a0fe5774f0d137e092a4eb9672a4518d0ef943a1a4619cb646a9ac9f74ee0"
		score = 75
		quality = 85
		tags = ""
		maltype = "KeyLogger"
		filetype = "exe"

	strings:
		$key = "HawkEyeKeylogger" wide
		$salt = "099u787978786" wide
		$string1 = "HawkEye_Keylogger" wide
		$string2 = "holdermail.txt" wide
		$string3 = "wallet.dat" wide
		$string4 = "Keylog Records" wide
		$string5 = "<!-- do not script -->" wide
		$string6 = "\\pidloc.txt" wide
		$string7 = "BSPLIT" wide

	condition:
		$key and $salt and all of ($string*)
}
