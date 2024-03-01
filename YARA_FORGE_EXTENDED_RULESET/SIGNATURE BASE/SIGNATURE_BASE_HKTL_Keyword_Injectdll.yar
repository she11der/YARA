rule SIGNATURE_BASE_HKTL_Keyword_Injectdll : FILE
{
	meta:
		description = "Detects suspicious InjectDLL keyword found in hacktools or possibly unwanted applications"
		author = "Florian Roth (Nextron Systems)"
		id = "422eed76-7dfa-5490-a866-d337434eaddc"
		date = "2019-04-04"
		modified = "2023-12-05"
		reference = "https://github.com/zerosum0x0/koadic"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_susp_hacktool.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "51c54026672e9ad36d2d68ae8dba61437f8808fbf2ad3c3c7bb086d8abb63987"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "2e7b4141e1872857904a0ef2d87535fd913cbdd9f964421f521b5a228a492a29"

	strings:
		$s2 = "InjectDLL" fullword ascii
		$s4 = "Kernel32.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
