rule SIGNATURE_BASE_RAT_Vertex
{
	meta:
		description = "Detects Vertex RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "f6f5967e-6b88-5d95-8fe1-a286ee8ce64c"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Vertex"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L915-L938"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c9fb0dedd97240ad29924865118ba34f5d79dbefbb13729d96d41336ec4de39e"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = "DEFPATH"
		$string2 = "HKNAME"
		$string3 = "HPORT"
		$string4 = "INSTALL"
		$string5 = "IPATH"
		$string6 = "MUTEX"
		$res1 = "PANELPATH"
		$res2 = "ROOTURL"

	condition:
		all of them
}
