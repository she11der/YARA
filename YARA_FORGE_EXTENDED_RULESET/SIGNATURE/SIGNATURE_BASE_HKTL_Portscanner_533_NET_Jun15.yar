rule SIGNATURE_BASE_HKTL_Portscanner_533_NET_Jun15 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c834203d-6d4d-5242-9b1e-b64fa6560ccd"
		date = "2015-06-13"
		modified = "2023-12-05"
		old_rule_name = "portscanner"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2188-L2205"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
		logic_hash = "446cbc1b8046bfd182e0b1c98fe37c8b8ef98f600f5d80d9de83b45aeaf2b386"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}
