import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fd8C468Cc1B45C9Cfb41Cbd8C835Cc9E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f0050a52-65d5-54b2-b06d-08812af98948"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6732-L6750"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "230d33f0d1d31d4cb76bf3b13f109d3cc9ace846daef145e1dc7666b33c8a42a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and (pe.signatures[i].serial=="00:fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e" or pe.signatures[i].serial=="fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e") and 1604019600<=pe.signatures[i].not_after)
}
