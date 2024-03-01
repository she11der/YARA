rule SIGNATURE_BASE_RAT_Infinity
{
	meta:
		description = "Detects Infinity RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "b70f9459-fa84-516f-841d-d9617856eb4d"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Infinity"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L391-L414"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c1f5381755af6cfbb10a4769757cdeffb9651bddc76bc4c8e9765ed44bf37fe6"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "CRYPTPROTECT_PROMPTSTRUCT"
		$b = "discomouse"
		$c = "GetDeepInfo"
		$d = "AES_Encrypt"
		$e = "StartUDPFlood"
		$f = "BATScripting" wide
		$g = "FBqINhRdpgnqATxJ.html" wide
		$i = "magic_key" wide

	condition:
		all of them
}
