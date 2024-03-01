import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A5B4F67Ad8B22Afc2Debe6Ce5F8F679 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7dd5ba42-2d04-52d7-b15a-2bdba2e742fb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8768-L8784"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "938efb7ee19970484aded5cd46b2ff730f8882706bec3f062bdebde3cc9a4799"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Farad LLC" and pe.signatures[i].serial=="0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79" and 1607472000<=pe.signatures[i].not_after)
}
