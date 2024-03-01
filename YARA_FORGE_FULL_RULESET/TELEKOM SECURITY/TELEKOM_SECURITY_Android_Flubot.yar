rule TELEKOM_SECURITY_Android_Flubot : FILE
{
	meta:
		description = "matches on dumped, decrypted V/DEX files of Flubot version > 4.2"
		author = "Thomas Barabosch, Telekom Security"
		id = "d6d1eebc-961f-5032-af04-4c95f364a74d"
		date = "2021-09-14"
		modified = "2021-09-14"
		reference = "https://github.com/telekom-security/malware_analysis/"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/flubot/flubot.yar#L1-L19"
		license_url = "N/A"
		hash = "37be18494cd03ea70a1fdd6270cef6e3"
		logic_hash = "db22e0890dfad7cb9cb1d18aadb406514e5e8874051aa7f07a4bb93da9db68df"
		score = 75
		quality = 45
		tags = "FILE"
		version = "20210720"

	strings:
		$dex = "dex"
		$vdex = "vdex"
		$s1 = "LAYOUT_MANAGER_CONSTRUCTOR_SIGNATURE"
		$s2 = "java/net/HttpURLConnection;"
		$s3 = "java/security/spec/X509EncodedKeySpec;"
		$s4 = "MANUFACTURER"

	condition:
		($dex at 0 or $vdex at 0) and 3 of ($s*)
}
