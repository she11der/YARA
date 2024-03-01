rule SIGNATURE_BASE_Kerberoast_PY
{
	meta:
		description = "Auto-generated rule - file kerberoast.py"
		author = "Florian Roth (Nextron Systems)"
		id = "cea6cdb2-cd1a-5701-a9d1-27c788a962a7"
		date = "2016-05-21"
		modified = "2023-12-05"
		reference = "https://github.com/skelsec/PyKerberoast"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_kerberoast.yar#L43-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3b285cc55733bd4c499ffb4821a92675806bf66faf3b3565ffb6de867bed538d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"

	strings:
		$s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
		$s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
		$s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
		$s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii

	condition:
		2 of them
}
