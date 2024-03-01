import "pe"

rule SIGNATURE_BASE_EQGRP_Eligiblecandidate
{
	meta:
		description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
		author = "Florian Roth (Nextron Systems)"
		id = "e084b051-4aa1-54b2-9f56-69db386b46d6"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L331-L348"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e7e1b206f9c51ffe0ab016a93d551a9ede8f87adfc38fe70278be8c2f0fe0696"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"

	strings:
		$o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
		$o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii
		$c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
		$c2 = "self.build_exploit_payload(cmd)" fullword ascii

	condition:
		1 of them
}
