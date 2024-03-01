rule SIGNATURE_BASE_RAT_Bozok
{
	meta:
		description = "Detects Bozok RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "b1d22e8c-39aa-52e7-9ca8-2b35bb82f7de"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Bozok"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L186-L206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9a2fcd11573654f0c91c0c0dec8938ca8319a23953a5043135cb0032562f9f53"
		score = 75
		quality = 75
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase

	condition:
		all of them
}
