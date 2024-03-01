rule SIGNATURE_BASE_Equationgroup__Scanner_Scanner_V2_1_2 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files scanner, scanner.v2.1.2"
		author = "Florian Roth (Nextron Systems)"
		id = "bf1f2119-f742-5106-96f0-de88755275ef"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L873-L892"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "3c42aaacea1347fd64d7f91421f692e77e33e273d4c2e71806ef7f5f086aba11"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
		hash2 = "9807aaa7208ed6c5da91c7c30ca13d58d16336ebf9753a5cea513bcb59de2cff"

	strings:
		$s1 = "Welcome to the network scanning tool" fullword ascii
		$s2 = "Scanning port %d" fullword ascii
		$s3 = "/current/down/cmdout/scans" fullword ascii
		$s4 = "Scan for SSH version" fullword ascii
		$s5 = "program vers proto   port  service" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <100KB and 2 of them ) or ( all of them )
}
