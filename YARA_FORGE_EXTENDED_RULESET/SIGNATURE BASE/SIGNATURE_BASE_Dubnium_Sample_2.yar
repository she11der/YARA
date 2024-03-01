rule SIGNATURE_BASE_Dubnium_Sample_2 : FILE
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth (Nextron Systems)"
		id = "894dc893-25fc-5fdc-9f69-8085b94e1af1"
		date = "2016-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/AW9Cuu"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_dubnium.yar#L26-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5b633a7e002609fa78b0de8fb818af1b47fbe77497d161b6b41602fb34780ca8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"

	strings:
		$x1 = ":*:::D:\\:c:~:" fullword ascii
		$s2 = "SPMUVR" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
