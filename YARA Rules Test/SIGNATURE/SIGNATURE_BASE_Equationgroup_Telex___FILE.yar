rule SIGNATURE_BASE_Equationgroup_Telex___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file telex"
		author = "Florian Roth (Nextron Systems)"
		id = "23571734-869d-5d68-9339-d82f168c2e47"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L258-L274"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9661bc43831307cb04883cfe8e54ebb2fe72bf3d7731b2b483cd19c40a5aeaa9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e9713b15fc164e0f64783e7a2eac189a40e0a60e2268bd7132cfdc624dfe54ef"

	strings:
		$x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
		$x2 = "target is not vulnerable. exiting" fullword ascii
		$s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
		$s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and 1 of them )
}