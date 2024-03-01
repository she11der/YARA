rule SIGNATURE_BASE_RAT_Bluebanana
{
	meta:
		description = "Detects BlueBanana RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "f00c7e92-f34c-5666-a1d9-02ac2cf7608c"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/BlueBanana"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L163-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0d84bb63d56d876c8b2e7c8c8afeaba839fee41d2d38f16ac9a13e802008179e"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "Java"

	strings:
		$meta = "META-INF"
		$conf = "config.txt"
		$a = "a/a/a/a/f.class"
		$b = "a/a/a/a/l.class"
		$c = "a/a/a/b/q.class"
		$d = "a/a/a/b/v.class"

	condition:
		all of them
}
