import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_967Cb0898680D1C174B2Baae5Fa332Db : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a95f7912-89fc-5c80-96ab-19e6ee2ccafd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8131-L8144"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8c68127b29d1a1aa4c1e2033c809fa57466f224c2bb4ede0ffb2b572a3d58c0f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c231f1e6cc3aec983d892e1bc3bb1815335fb24e3e2f611d79bade9a07cbd819"
		reason = "Babadeda"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "James Caulfield" and pe.signatures[i].serial=="96:7c:b0:89:86:80:d1:c1:74:b2:ba:ae:5f:a3:32:db")
}
