rule SIGNATURE_BASE_Equationgroup_Ewok : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
		author = "Florian Roth (Nextron Systems)"
		id = "379c233f-86f8-5116-a15c-8a80b27daea6"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L768-L784"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d10d75885daa8cd20e5d7d7e142d1e7a2dbc10a50debf7892629f67b948bbdbe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"

	strings:
		$x1 = "Example: ewok -t target public" fullword ascii
		$x2 = "Usage:  cleaner host community fake_prog" fullword ascii
		$x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
		$x4 = "--- ewok version" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <80KB and 1 of them )
}
