rule SIGNATURE_BASE_Wildneutron_Sample_7 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "22561c55-4294-50c9-a9b9-7b4ed98eec09"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_wildneutron.yar#L151-L176"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
		logic_hash = "8a081932be8fd03c37a87486570a02a31756ba6bd125dbed7da9703197447ea5"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "checking match for '%s' user %s host %s addr %s" fullword ascii
		$s1 = "PEM_read_bio_PrivateKey failed" fullword ascii
		$s2 = "usage: %s [-ehR] [-f log_facility] [-l log_level] [-u umask]" fullword ascii
		$s3 = "%s %s for %s%.100s from %.200s port %d%s" fullword ascii
		$s4 = "clapi32.dll" fullword ascii
		$s5 = "Connection from %s port %d" fullword ascii
		$s6 = "/usr/etc/ssh_known_hosts" fullword ascii
		$s7 = "Version: %s - %s %s %s %s" fullword ascii
		$s8 = "[-] connect()" fullword ascii
		$s9 = "/bin/sh /usr/etc/sshrc" fullword ascii
		$s10 = "kexecdhs.c" fullword ascii
		$s11 = "%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of them
}
