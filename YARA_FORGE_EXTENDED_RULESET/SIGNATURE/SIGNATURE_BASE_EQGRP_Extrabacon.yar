import "pe"

rule SIGNATURE_BASE_EQGRP_Extrabacon
{
	meta:
		description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
		author = "Florian Roth (Nextron Systems)"
		id = "79b998ef-e548-5038-b8ad-da1abf362e7f"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L708-L725"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1a010d5e6324715f8e1bf29e957c365fabd2986fece53aaea23bba8ee59bd808"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"

	strings:
		$x1 = "To disable password checking on target:" fullword ascii
		$x2 = "[-] target is running" fullword ascii
		$x3 = "[-] problem importing version-specific shellcode from" fullword ascii
		$x4 = "[+] importing version-specific shellcode" fullword ascii
		$s5 = "[-] unsupported target version, abort" fullword ascii

	condition:
		1 of them
}
