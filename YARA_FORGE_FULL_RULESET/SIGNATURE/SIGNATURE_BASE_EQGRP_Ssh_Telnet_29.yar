import "pe"

rule SIGNATURE_BASE_EQGRP_Ssh_Telnet_29 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
		author = "Florian Roth (Nextron Systems)"
		id = "cc6edf63-f7ef-579a-82c5-28e5012561e0"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1220-L1241"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e93a54f4de089d460bfb966feacc377c0467863f481a210c81970f4909fb3bd8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
		hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"

	strings:
		$s1 = "received prompt, we're in" fullword ascii
		$s2 = "failed to login, bad creds, abort" fullword ascii
		$s3 = "sending command \" + str(n) + \"/\" + str(tot) + \", len \" + str(len(chunk) + " fullword ascii
		$s4 = "received nat - EPBA: ok, payload: mangled, did not run" fullword ascii
		$s5 = "no status returned from target, could be an exploit failure, or this is a version where we don't expect a stus return" ascii
		$s6 = "received arp - EPBA: ok, payload: fail" fullword ascii
		$s7 = "chopped = string.rstrip(payload, \"\\x0a\")" fullword ascii

	condition:
		( filesize <10KB and 2 of them ) or (3 of them )
}
