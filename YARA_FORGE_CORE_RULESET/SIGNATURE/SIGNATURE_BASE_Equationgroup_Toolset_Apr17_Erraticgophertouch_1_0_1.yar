rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Erraticgophertouch_1_0_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "9f03a4b6-69ab-5cef-876c-1e86ef2afe10"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1636-L1651"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "08646f7887daddd8efac875bc7b111df7a52feae0a4b81bfd2d2ae7ef9453b5e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "729eacf20fe71bd74e57a6b829b45113c5d45003933118b53835779f0b049bad"

	strings:
		$x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
		$x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
		$x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and 1 of them )
}
