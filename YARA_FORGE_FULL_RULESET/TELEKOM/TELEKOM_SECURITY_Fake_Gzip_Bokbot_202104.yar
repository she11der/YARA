rule TELEKOM_SECURITY_Fake_Gzip_Bokbot_202104
{
	meta:
		description = "fake gzip provided by CC"
		author = "Thomas Barabosch, Telekom Security"
		id = "538d84d8-aff2-571c-ba60-102f18262434"
		date = "2021-04-20"
		modified = "2021-07-08"
		reference = "https://github.com/telekom-security/malware_analysis/"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/icedid/icedid_20210507.yar#L1-L11"
		license_url = "N/A"
		logic_hash = "0f0205234eae1b011b899a59e4430c2de9d913b05efee90ce844a06f1cff04f3"
		score = 75
		quality = 70
		tags = ""

	strings:
		$gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}

	condition:
		$gzip at 0
}
