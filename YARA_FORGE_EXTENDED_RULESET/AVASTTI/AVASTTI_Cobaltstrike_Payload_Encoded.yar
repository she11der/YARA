rule AVASTTI_Cobaltstrike_Payload_Encoded
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "b5176740-2dda-5e5d-8c0f-47a27846753d"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L542-L593"
		license_url = "N/A"
		logic_hash = "03c650b3c1797c03c635e25ea9d1d4589c6a4b31da0a3e48631fa16d0e3a342b"
		score = 75
		quality = 68
		tags = ""

	strings:
		$s01 = "0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30, 0x8b" ascii wide nocase
		$s02 = "0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b" ascii wide nocase
		$s03 = "0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51" ascii wide nocase
		$s04 = "0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51" ascii wide nocase
		$s05 = "fce8890000006089e531d2648b52308b" ascii wide nocase
		$s06 = "fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b" ascii wide nocase
		$s07 = "fc4883e4f0e8c8000000415141505251" ascii wide nocase
		$s08 = "fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51" ascii wide nocase
		$s09 = "/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJX" ascii wide
		$s10 = "/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHA" ascii wide
		$s11 = "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0" ascii wide
		$s12 = "32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLj" ascii wide
		$s13 = "/ADoAIkAAAAAAAAAYACJAOUAMQDSAGQAiwBSADAAiwBSAAwAiwBSABQAiwByACg" ascii wide
		$s14 = "/ABIAIMA5ADwAOgAyAAAAAAAAABBAFEAQQBQAFIAUQBWAEgAMQDSAGUASACLAFI" ascii wide
		$s15 = "3yPLI6ojIyMjIyMjQyOqI8YjEiPxI0cjqCNxIxMjqCNxIy8jqCNxIzcjqCNRIwsj" ascii wide
		$s16 = "3yNrI6AjxyPTI8sj6yMjIyMjIyNiI3IjYiNzI3EjciN1I2sjEiPxI0YjayOoI3Ej" ascii wide
		$s17 = "Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117" ascii wide
		$s18 = "Array(-4, -24, -119, 0, 0, 0, 96, -119, -27, 49, -46, 100, -117, 82, 48, -117" ascii wide
		$s19 = "Array(-4,72,-125,-28,-16,-24,-56,0,0,0,65,81,65,80,82,81" ascii wide
		$s20 = "Array(-4, 72, -125, -28, -16, -24, -56, 0, 0, 0, 65, 81, 65, 80, 82, 81" ascii wide
		$s21 = "Chr(-4)&Chr(-24)&Chr(-119)&Chr(0)&Chr(0)&Chr(0)&Chr(96)&Chr(-119)&Chr(-27)&\"1\"&Chr(-46)&\"d\"&Chr(-117)&\"R0\"&Chr(-117)" ascii wide
		$s22 = "Chr(-4)&\"H\"&Chr(-125)&Chr(-28)&Chr(-16)&Chr(-24)&Chr(-56)&Chr(0)&Chr(0)&Chr(0)&\"AQAPRQVH" ascii wide
		$s23 = "\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b" ascii wide nocase
		$s24 = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51" ascii wide nocase

	condition:
		any of them
}
