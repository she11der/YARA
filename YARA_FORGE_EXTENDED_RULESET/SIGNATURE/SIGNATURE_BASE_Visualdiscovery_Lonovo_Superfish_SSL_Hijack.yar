rule SIGNATURE_BASE_Visualdiscovery_Lonovo_Superfish_SSL_Hijack : FILE
{
	meta:
		description = "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"
		author = "Florian Roth (Nextron Systems) / improved by kbandla"
		id = "200c016e-7ad8-5b58-be5f-7866e91d60e9"
		date = "2015-02-19"
		modified = "2023-12-05"
		reference = "https://twitter.com/4nc4p/status/568325493558272000"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/threat_lenovo_superfish.yar#L4-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0f156a51dccafe32467b64251507928b1c7a1b04595063aa66aa69da6c4cc4fc"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "99af9cfc7ab47f847103b5497b746407dc566963"
		hash2 = "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46"
		hash3 = "f12edf2598d8f0732009c5cd1df5d2c559455a0b"
		hash4 = "343af97d47582c8150d63cbced601113b14fcca6"

	strings:
		$s2 = "Invalid key length used to initialize BlowFish." fullword ascii
		$s3 = "GetPCProxyHandler" fullword ascii
		$s4 = "StartPCProxy" fullword ascii
		$s5 = "SetPCProxyHandler" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2MB and all of ($s*)
}
