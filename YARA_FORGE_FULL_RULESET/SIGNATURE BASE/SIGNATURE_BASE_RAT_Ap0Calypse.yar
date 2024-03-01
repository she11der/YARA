rule SIGNATURE_BASE_RAT_Ap0Calypse
{
	meta:
		description = "Detects Ap0calypse RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "a2993654-efa0-519b-b6f6-4d722d93adde"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Ap0calypse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L50-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1ce90a5b1b3f643d4e530d6e00741f5d5918d3199cfbc4126cf8421a9e42023e"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}
