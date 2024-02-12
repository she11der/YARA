rule SIGNATURE_BASE_Equationgroup__Funnelout_V4_1_0_1___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files funnelout.v4.1.0.1.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "b0c42b06-8314-5731-b333-59bb90785cf4"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L952-L969"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ae0b387725017de2766593ea55677dca36eee68107e0692a7d5e2526db74765b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash2 = "457ed14e806fdbda91c4237c8dc058c55e5678f1eecdd78572eff6ca0ed86d33"

	strings:
		$s1 = "header(\"Set-Cookie: bbsessionhash=\" . \\$hash . \"; path=/; HttpOnly\");" fullword ascii
		$s2 = "if ($code =~ /proxyhost/) {" fullword ascii
		$s3 = "\\$rk[1] = \\$rk[1] - 1;" ascii
		$s4 = "#existsUser($u) or die \"User '$u' does not exist in database.\\n\";" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <100KB and 2 of them ) or ( all of them )
}