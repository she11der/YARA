rule SIGNATURE_BASE_M_Hunting_Backdoor_ZIPLINE_1 : FILE
{
	meta:
		description = "This rule detects unique strings in ZIPLINE, a passive ELF backdoor that waits for incoming TCP connections to receive commands from the threat actor."
		author = "Mandiant"
		id = "753884d6-d4c1-5e94-9d2c-f6ebb7bfaf85"
		date = "2024-01-11"
		modified = "2024-01-12"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_report_ivanti_mandiant_jan24.yar#L17-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "41857ba465dd1f2e1aa8c1eed36b73606385eeedf233fd480bb8a4ef15499174"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "SSH-2.0-OpenSSH_0.3xx" ascii
		$s2 = "$(exec $installer $@)" ascii
		$t1 = "./installer/do-install" ascii
		$t2 = "./installer/bom_files/" ascii
		$t3 = "/tmp/data/root/etc/ld.so.preload" ascii
		$t4 = "/tmp/data/root/home/etc/manifest/exclusion_list" ascii

	condition:
		uint32(0)==0x464c457f and filesize <5MB and ((1 of ($s*)) or (3 of ($t*)))
}
