rule SIGNATURE_BASE_RAT_Unrecom
{
	meta:
		description = "Detects unrecom RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "56b11c22-f43c-5192-9a0a-0ac14b0cd041"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/unrecom"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L1038-L1058"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "15ab9ee2f3fd825e91813a185bc5c7d7e790de39cd3e88c375b801d1412a08f4"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$meta = "META-INF"
		$conf = "load/ID"
		$a = "load/JarMain.class"
		$b = "load/MANIFEST.MF"
		$c = "plugins/UnrecomServer.class"

	condition:
		all of them
}
