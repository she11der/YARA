import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_13C7B92282Aae782Bfb00Baf879935F4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "244ff442-0bce-5f9f-85ea-33fafe9a2e7b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1819-L1830"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2742fd71eb8219db7785ad46be18a906fdab0914f632dfbf531238fd551a5b65"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c253cce2094c0a4ec403518d4fbf18c650e5434759bc690758cb3658b75c8baa"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and pe.signatures[i].serial=="13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4")
}
