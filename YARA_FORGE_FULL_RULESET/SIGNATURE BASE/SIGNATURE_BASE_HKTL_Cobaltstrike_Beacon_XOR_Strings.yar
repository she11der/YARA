rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_XOR_Strings
{
	meta:
		description = "Identifies XOR'd strings used in Cobalt Strike Beacon DLL"
		author = "Elastic"
		id = "359160a8-cf1c-58a8-bf7f-c09a8d661308"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cobaltstrike.yar#L69-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b5009c29055784ce6371100417b862f723d7e3c1b4081c563fcd8770db48051f"
		score = 75
		quality = 85
		tags = ""
		xor_s1 = "%02d/%02d/%02d %02d:%02d:%02d"
		xor_s2 = "Started service %s on %s"
		xor_s3 = "%s as %s\\%s: %d"

	strings:
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x01-0xff)
		$s2 = "Started service %s on %s" xor(0x01-0xff)
		$s3 = "%s as %s\\%s: %d" xor(0x01-0xff)
		$fp1 = "MalwareRemovalTool"

	condition:
		2 of ($s*) and not 1 of ($fp*)
}
