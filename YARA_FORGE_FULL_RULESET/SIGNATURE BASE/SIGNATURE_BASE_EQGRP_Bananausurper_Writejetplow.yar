import "pe"

rule SIGNATURE_BASE_EQGRP_Bananausurper_Writejetplow : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
		author = "Florian Roth (Nextron Systems)"
		id = "901af182-cbfa-533a-a055-565d95005d62"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1009-L1028"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "101e75800291a7603e03145bff298d7587c9b5f19102e7ba9ed3bf2b544fa5cf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$x1 = "Implant Version-Specific Values:" fullword ascii
		$x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii
		$s1 = "createSendRecv: recv'd an error from the target." fullword ascii
		$s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <2000KB and 1 of ($x*)) or (3 of them )
}
