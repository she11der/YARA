import "pe"

rule SIGNATURE_BASE_EQGRP_BBALL_M50FW08_2201 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L505-L523"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dd180203ec4c4ddfa2c46cba672eb94179553637a9f7548b25dee7b88c3d3294"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"

	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "pageTable.c" fullword ascii
		$s4 = "_start_text" ascii
		$s5 = "handler_readBIOS" fullword ascii
		$s6 = "KEEPGOING" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and 5 of ($s*))
}
