import "pe"

rule REVERSINGLABS_Cert_Blocklist_04C8Eca7243208A110Dea926C7Ad89Ce : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "484d0aa6-0447-5e60-946b-89b01a5e43dd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1472-L1488"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0012436e83704397026a8b2e500e5d61915e0f4c8ad4100176e200a975562e8f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, SINGH ADITYA" and pe.signatures[i].serial=="04:c8:ec:a7:24:32:08:a1:10:de:a9:26:c7:ad:89:ce" and 1404172799<=pe.signatures[i].not_after)
}
