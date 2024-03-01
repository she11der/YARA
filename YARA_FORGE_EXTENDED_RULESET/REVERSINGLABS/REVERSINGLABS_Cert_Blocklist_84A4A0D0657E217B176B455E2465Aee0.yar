import "pe"

rule REVERSINGLABS_Cert_Blocklist_84A4A0D0657E217B176B455E2465Aee0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1484a28d-ce7c-506f-8cbb-73ac541a0907"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11784-L11802"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "92f6e90bd21182bece68ac1651105f96a18c5b1497d30e0040a978e349341bdb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AATB ApS" and (pe.signatures[i].serial=="00:84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0" or pe.signatures[i].serial=="84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0") and 1616457600<=pe.signatures[i].not_after)
}
