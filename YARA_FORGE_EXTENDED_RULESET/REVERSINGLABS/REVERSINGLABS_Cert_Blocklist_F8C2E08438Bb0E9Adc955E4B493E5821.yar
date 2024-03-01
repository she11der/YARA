import "pe"

rule REVERSINGLABS_Cert_Blocklist_F8C2E08438Bb0E9Adc955E4B493E5821 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "65297530-2482-5773-8914-461fb56cb41d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5138-L5156"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5dbe554032c945c46ffd61ef1e0deb59d396a70dd63994bf44c65d849ec8220a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and (pe.signatures[i].serial=="00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21" or pe.signatures[i].serial=="f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21") and 1599523200<=pe.signatures[i].not_after)
}
