rule SIGNATURE_BASE_Ysoserial_Payload_Spring1
{
	meta:
		description = "Ysoserial Payloads - file Spring1.bin"
		author = "Florian Roth (Nextron Systems)"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://github.com/frohoff/ysoserial"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_ysoserial_payloads.yar#L40-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "852390d242c5cac243b54c31234c0ef3e25cede376eea23c73f03d79c548be8a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
		hash2 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
		hash3 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
		hash4 = "5c44482350f1c6d68749c8dec167660ca6427999c37bfebaa54f677345cdf63c"
		hash5 = "95f966f2e8c5d0bcdfb34e603e3c0b911fa31fc960308e41fcd4459e4e07b4d1"
		hash6 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
		hash7 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"

	strings:
		$x1 = "ysoserial/Pwner" ascii

	condition:
		1 of them
}
