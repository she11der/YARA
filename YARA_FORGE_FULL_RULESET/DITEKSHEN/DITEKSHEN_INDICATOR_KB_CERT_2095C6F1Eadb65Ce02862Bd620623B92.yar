import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2095C6F1Eadb65Ce02862Bd620623B92 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c44d8942-569b-50c6-8363-0576c7d54dfb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3347-L3358"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0b75d8c59486d197f2cdff298114a7367bb6ad4cf71ee28273e0946e42d3f7e8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "940a4d4a5aadef70d8c14caac6f11d653e71800f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Febeecad" and pe.signatures[i].serial=="20:95:c6:f1:ea:db:65:ce:02:86:2b:d6:20:62:3b:92")
}
