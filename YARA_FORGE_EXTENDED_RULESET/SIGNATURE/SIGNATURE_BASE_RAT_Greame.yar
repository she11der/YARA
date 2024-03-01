rule SIGNATURE_BASE_RAT_Greame
{
	meta:
		description = "Detects Greame RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "b90d3747-407a-5552-971f-78ff78f827a6"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Greame"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L308-L331"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4a1ce5f5847bdc01d286c1d9cd1e16ba2fd6b5bc56e6094cb1492882708e8e59"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$c = "EditSvr"
		$d = "TLoader"
		$e = "Stroks"
		$f = "Avenger by NhT"
		$g = "####@####"
		$h = "GREAME"

	condition:
		all of them
}
