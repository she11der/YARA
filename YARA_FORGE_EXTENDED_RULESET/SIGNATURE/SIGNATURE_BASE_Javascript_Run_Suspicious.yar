rule SIGNATURE_BASE_Javascript_Run_Suspicious
{
	meta:
		description = "Detects a suspicious Javascript Run command"
		author = "Florian Roth (Nextron Systems)"
		id = "87f98ead-3052-5777-8877-574619173aaa"
		date = "2017-08-23"
		modified = "2023-12-05"
		reference = "https://twitter.com/craiu/status/900314063560998912"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mal_scripts.yar#L52-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "39d2292d3749c63780dc7ca7a2414ba02e2b0e1edec7ec6a16b42aba2c44c23a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "w = new ActiveXObject(" ascii
		$s2 = " w.Run(r);" fullword ascii

	condition:
		all of them
}
