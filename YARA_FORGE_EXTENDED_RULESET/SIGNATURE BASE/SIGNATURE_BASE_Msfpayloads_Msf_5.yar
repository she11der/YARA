rule SIGNATURE_BASE_Msfpayloads_Msf_5
{
	meta:
		description = "Metasploit Payloads - file msf.msi"
		author = "Florian Roth (Nextron Systems)"
		id = "030d1982-c9a8-539d-a995-7901ae425857"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L141-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "cb602670329391b091f87818a0f5defaa8f688f7921978510739b96ca63a2f12"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"

	strings:
		$s1 = "required to install Foobar 1.0." fullword ascii
		$s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
		$s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii

	condition:
		all of them
}
