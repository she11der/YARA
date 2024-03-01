import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E339C8069126Aa6313484Fea85B4B326F7B8860C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a8a6a285-98e1-5a2a-ab89-c67809fea3b2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6001-L6012"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6f373c5a8f99893088fa1afffeccdf24ae6ed118d7bea9df43281073bd8e85bb"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e339c8069126aa6313484fea85b4b326f7b8860c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Germany classer software" and pe.signatures[i].serial=="01")
}
