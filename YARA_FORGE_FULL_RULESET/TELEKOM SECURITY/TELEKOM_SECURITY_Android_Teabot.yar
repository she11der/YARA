rule TELEKOM_SECURITY_Android_Teabot : FILE
{
	meta:
		description = "matches on dumped, decrypted V/DEX files of Teabot"
		author = "Thomas Barabosch, Telekom Security"
		id = "9db701bf-be84-5236-97f7-67043cf3ea93"
		date = "2021-09-14"
		modified = "2021-09-14"
		reference = "https://github.com/telekom-security/malware_analysis/"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/flubot/teabot.yar#L1-L23"
		license_url = "N/A"
		hash = "37be18494cd03ea70a1fdd6270cef6e3"
		logic_hash = "5aa7fdb191c36510c7698f3eae40c0b7f15c944b8f60113bbb4e40fc926579b8"
		score = 75
		quality = 45
		tags = "FILE"
		version = "20210819"

	strings:
		$dex = "dex"
		$vdex = "vdex"
		$s1 = "ERR 404: Unsupported device"
		$s2 = "Opening inject"
		$s3 = "Prevented samsung power off"
		$s4 = "com.huawei.appmarket"
		$s5 = "kill_bot"
		$s6 = "kloger:"
		$s7 = "logged_sms"
		$s8 = "xiaomi_autostart"

	condition:
		($dex at 0 or $vdex at 0) and 6 of ($s*)
}
