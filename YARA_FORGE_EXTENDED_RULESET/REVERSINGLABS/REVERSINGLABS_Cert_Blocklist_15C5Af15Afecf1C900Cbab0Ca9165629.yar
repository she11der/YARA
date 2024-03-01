import "pe"

rule REVERSINGLABS_Cert_Blocklist_15C5Af15Afecf1C900Cbab0Ca9165629 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "de734943-e735-5895-b76e-5f8588a77540"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4198-L4214"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5c54f32dbac271b2b60ec40bd052b5566a512cd2bcb4255057b21262806882d2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kompaniya Auttek" and pe.signatures[i].serial=="15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29" and 1586091840<=pe.signatures[i].not_after)
}
