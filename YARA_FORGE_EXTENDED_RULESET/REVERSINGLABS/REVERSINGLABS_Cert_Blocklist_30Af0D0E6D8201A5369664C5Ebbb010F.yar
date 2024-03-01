import "pe"

rule REVERSINGLABS_Cert_Blocklist_30Af0D0E6D8201A5369664C5Ebbb010F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aaa31642-a0f4-5652-b3cd-c81cfb1ab127"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7652-L7668"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "018e5a0fbeeaded2569b83e2f91230e0055a5ffa2059b7a064a5c2eda55ed2de"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3N-\\xC5\\xA0PORT podjetje za in\\xC5\\xBEeniring, storitve in trgovino d.o.o." and pe.signatures[i].serial=="30:af:0d:0e:6d:82:01:a5:36:96:64:c5:eb:bb:01:0f" and 1613433600<=pe.signatures[i].not_after)
}
