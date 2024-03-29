import "pe"

rule SIGNATURE_BASE_Linuxhacktool_Eyes_Pscan2_2
{
	meta:
		description = "Linux hack tools - file pscan2.c"
		author = "Florian Roth (Nextron Systems)"
		id = "3950b235-70bc-5afd-add5-38c50055b28b"
		date = "2015-01-19"
		modified = "2023-12-05"
		reference = "not set"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2908-L2925"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
		logic_hash = "981514cf0887a1a7cb55fe9ed9dadd48adbf0f033e527b357e90e052a4c2d251"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
		$s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
		$s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
		$s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
		$s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii

	condition:
		2 of them
}
