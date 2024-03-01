import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ac3C05F1Cb9453De8E7110F589Fb32C0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2578655e-6420-5a67-9116-cab5cf5bc195"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9668-L9686"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6328fd5dbb497c69ddc9151f85754669760b709ecbff3e8f320a40a62ca0dd2c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRAIN BUILDING TEAM s.r.o." and (pe.signatures[i].serial=="00:ac:3c:05:f1:cb:94:53:de:8e:71:10:f5:89:fb:32:c0" or pe.signatures[i].serial=="ac:3c:05:f1:cb:94:53:de:8e:71:10:f5:89:fb:32:c0") and 1635854205<=pe.signatures[i].not_after)
}
