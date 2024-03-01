rule SIGNATURE_BASE_RAT_Spygate
{
	meta:
		description = "Detects SpyGate RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "ed015770-81ff-5d9c-8bd0-3c225e400724"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/SpyGate"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L863-L890"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5b891212f3a669c6066cfddef418faafd75c92bb2f1e8e1f48403422a73bc9fa"
		score = 75
		quality = 83
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$split = "abccba"
		$a1 = "abccbaSpyGateRATabccba"
		$a2 = "StubX.pdb"
		$a3 = "abccbaDanabccb"
		$b1 = "monikerString" nocase
		$b2 = "virustotal1"
		$b3 = "get_CurrentDomain"
		$c1 = "shutdowncomputer" wide
		$c2 = "shutdown -r -t 00" wide
		$c3 = "set cdaudio door closed" wide
		$c4 = "FileManagerSplit" wide
		$c5 = "Chating With >> [~Hacker~]" wide

	condition:
		( all of ($a*) and #split>40) or ( all of ($b*) and #split>10) or ( all of ($c*))
}
