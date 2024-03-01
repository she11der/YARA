import "pe"

rule SIGNATURE_BASE_EQGRP_Tunnel_State_Reader
{
	meta:
		description = "EQGRP Toolset Firewall - file tunnel_state_reader"
		author = "Florian Roth (Nextron Systems)"
		id = "e48c9482-eae5-5c34-b7b2-502d0252f4a0"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L299-L313"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d0653650aad10e7ff69b7ef1e61fac64310c63cc68c6d924655f082925e4fd04"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"

	strings:
		$s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
		$s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii

	condition:
		1 of them
}
