rule SIGNATURE_BASE_WAF_Bypass : FILE
{
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d9f40934-873b-5e73-9198-987966027edc"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L30-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"
		logic_hash = "e66d51b465e5d919555084d299a22f07a949a0a9adf4a3f246f6b5222d39b91a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Email: blacksplitn@gmail.com" fullword wide
		$s2 = "User-Agent:" fullword wide
		$s3 = "Send Failed.in RemoteThread" fullword ascii
		$s4 = "www.example.com" fullword wide
		$s5 = "Get Domain:%s IP Failed." fullword ascii
		$s6 = "Connect To Server Failed." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <7992KB and 5 of them
}
