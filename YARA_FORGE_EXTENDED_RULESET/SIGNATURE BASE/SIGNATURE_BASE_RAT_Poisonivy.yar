rule SIGNATURE_BASE_RAT_Poisonivy
{
	meta:
		description = "Detects PoisonIvy RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "371686d3-878f-56fc-a702-ec49845f486b"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/PoisonIvy"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L651-L672"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "874e0dfb22a03abc0f7fdc7209ff13b55dfa5dcc17db944903ca37a549eb331d"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
		$string1 = "CONNECT %s:%i HTTP/1.0"
		$string2 = "ws2_32"
		$string3 = "cks=u"
		$string4 = "thj@h"
		$string5 = "advpack"

	condition:
		$stub at 0x1620 and all of ($string*) or ( all of them )
}
