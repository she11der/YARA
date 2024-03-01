rule SIGNATURE_BASE_Equationgroup_Eh_1_1_0 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
		author = "Florian Roth (Nextron Systems)"
		id = "a6f0ec1f-b0e5-5913-970d-9cdadf647c44"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L153-L168"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d0972bb57076606b3c84f3cbbb0be85cd5663c7cd6f6d9f09a2991cb6532bfa9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0f8dd094516f1be96da5f9addc0f97bcac8f2a348374bd9631aa912344559628"

	strings:
		$x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
		$x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
		$x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <100KB and 1 of them )
}
