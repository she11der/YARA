rule SIGNATURE_BASE_Equationdrug_Compatlayer_Unilaydll : FILE
{
	meta:
		description = "EquationDrug - Unilay.DLL"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "32fd31c7-cc44-50e1-8888-b9da59ce587b"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L390-L402"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a3a31937956f161beba8acac35b96cb74241cd0f"
		logic_hash = "86434bd0456ea0c9ac9ed74dc3cf63520eb6b880dd4ea7920d0e82873dfec21e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "unilay.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and $s0
}
