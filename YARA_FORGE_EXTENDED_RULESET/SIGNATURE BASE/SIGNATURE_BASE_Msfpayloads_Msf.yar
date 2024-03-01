rule SIGNATURE_BASE_Msfpayloads_Msf : FILE
{
	meta:
		description = "Metasploit Payloads - file msf.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "c56dbb8e-1e03-5112-b2ef-a0adfd14dffa"
		date = "2017-02-09"
		modified = "2022-08-18"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L10-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4f0eab53a135242c7891b8c88e937a854c945a10000ca4cbf7b21f4596dca410"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"

	strings:
		$s1 = "export buf=\\" ascii

	condition:
		filesize <5MB and $s1
}
