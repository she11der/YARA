rule SIGNATURE_BASE_FE_APT_Trojan_PL_RADIALPULSE_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "1fab6d2f-96e8-5def-a93e-2bddd04e7ec8"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_pulsesecure.yar#L173-L190"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d72daafedf41d484f7f9816f7f076a9249a6808f1899649b7daa22c0447bb37b"
		logic_hash = "d65a466cc15214d8e26597588c039a6b9fb4637ef8f3b1ebea27f016fbd5cba8"
		score = 75
		quality = 83
		tags = ""

	strings:
		$s1 = "->getRealmInfo()->{name}"
		$s2 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>/
		$s3 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]realm=\$/
		$s4 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]username=\$/
		$s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]password=\$/

	condition:
		(@s1[1]<@s2[1]) and (@s2[1]<@s3[1]) and $s4 and $s5
}
