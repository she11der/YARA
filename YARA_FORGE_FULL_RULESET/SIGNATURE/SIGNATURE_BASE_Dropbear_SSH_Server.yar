rule SIGNATURE_BASE_Dropbear_SSH_Server : FILE
{
	meta:
		description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
		author = "Florian Roth (Nextron Systems)"
		id = "22595d8b-b7ea-570e-ad17-d5bcec613abf"
		date = "2016-01-03"
		modified = "2023-12-05"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_blackenergy.yar#L51-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
		logic_hash = "6b8acaaa64329d09d3d22d74f4f40288fba3f5faaff63e1ee6b2e6153f14d730"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
		$s2 = "Badly formatted command= authorized_keys option" fullword ascii
		$s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
		$s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
		$s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}
