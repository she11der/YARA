rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Stage3_Persistence
{
	meta:
		description = "HyperBro Stage 3 registry keys for persistence"
		author = "Marko Dorfhuber"
		id = "2bb1d28b-5fc4-5f0b-b546-c8b8192b0d48"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_apt27_hyperbro.yar#L103-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "db4b7be2bafe29b5e7c81a90e17a660cf73cff1c2e8edd04a9421daba09e3e0e"
		score = 75
		quality = 85
		tags = ""
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"

	strings:
		$ = "SOFTWARE\\WOW6432Node\\Microsoft\\config_" ascii
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\windefenders" ascii

	condition:
		1 of them
}