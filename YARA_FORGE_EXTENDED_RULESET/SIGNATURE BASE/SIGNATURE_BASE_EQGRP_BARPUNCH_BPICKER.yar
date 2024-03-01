import "pe"

rule SIGNATURE_BASE_EQGRP_BARPUNCH_BPICKER : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
		author = "Florian Roth (Nextron Systems)"
		id = "7e88ba9d-1f15-533a-b388-a2a027ddb07c"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L902-L921"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f5d0cc881bedad736a90109933da8dbd32c4435aa255676c68ae3541bbb61e74"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

	strings:
		$x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
		$x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
		$x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
		$x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
		$x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <6000KB and 1 of them ) or (3 of them )
}
