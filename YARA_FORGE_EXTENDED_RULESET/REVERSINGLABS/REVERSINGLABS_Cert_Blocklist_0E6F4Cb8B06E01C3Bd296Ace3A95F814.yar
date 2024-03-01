import "pe"

rule REVERSINGLABS_Cert_Blocklist_0E6F4Cb8B06E01C3Bd296Ace3A95F814 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7a829a63-eeb4-50ef-829d-fc13572c1148"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6828-L6844"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f3184a9d1fe2a1cf2dcc04d26c284aa9a651d2f00aa28642d7f951550a050138"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EVATON, s.r.o." and pe.signatures[i].serial=="0e:6f:4c:b8:b0:6e:01:c3:bd:29:6a:ce:3a:95:f8:14" and 1603957781<=pe.signatures[i].not_after)
}
