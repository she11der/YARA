import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_15C5Af15Afecf1C900Cbab0Ca9165629 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "795fa78b-0cd4-5eb4-9d37-72b5c38e7466"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7587-L7599"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "cfc72a85954cb12d89a09b47b5937216a7cfee4a71ac6335a2a94faadea1f68c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "69735ec138c555d9a0d410c450d8bcc7c222e104"
		hash1 = "2ae575f006fc418c72a55ec5fdc26bc821aa3929114ee979b7065bf5072c488f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kompaniya Auttek" and pe.signatures[i].serial=="15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29")
}
