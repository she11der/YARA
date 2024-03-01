rule SIGNATURE_BASE_FE_APT_Trojan_PL_QUIETPULSE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "4c49eef7-b8fa-55d5-8fb8-8964f6f50003"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_pulsesecure.yar#L154-L172"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "00575bec8d74e221ff6248228c509a16"
		logic_hash = "226a56369e141834d4834400bbf1a006bbb6e9b39e16e24b0106bff1a9c202a9"
		score = 75
		quality = 83
		tags = ""

	strings:
		$s1 = /open[\x09\x20]{0,32}\(\*STDOUT[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/
		$s2 = /open[\x09\x20]{0,32}\(\*STDERR[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/
		$s3 = /socket[\x09\x20]{0,32}\(SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}PF_UNIX[\x09\x20]{0,32},[\x09\x20]{0,32}SOCK_STREAM[\x09\x20]{0,32},[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{0,128}unlink/
		$s4 = /bind[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}sockaddr_un\(/
		$s5 = /listen[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}SOMAXCONN[\x09\x20]{0,32}\)[\x09\x20]{0,32};/
		$s6 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}fork\([\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{1,128}if[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}==[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{\s{1,128}exec\(/

	condition:
		all of them
}
