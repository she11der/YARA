rule SIGNATURE_BASE_RAT_AAR
{
	meta:
		description = "Detects AAR RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "42c1af80-cff3-505f-a3cb-35b7e34575e1"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/AAR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L1-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a206b3f5cf6cc870135bc267b5baab8333422dc917efce6c66ee907690592d09"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Hashtable"
		$b = "get_IsDisposed"
		$c = "TripleDES"
		$d = "testmemory.FRMMain.resources"
		$e = "$this.Icon" wide
		$f = "{11111-22222-20001-00001}" wide

	condition:
		all of them
}
