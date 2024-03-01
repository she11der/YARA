import "pe"

rule REVERSINGLABS_Cert_Blocklist_0860C8A7Ed18C3F030A32722Fd2B220C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "335a1cd3-520a-5f0f-abda-6ec8a122de4b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1582-L1598"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3c777fb157a6669bfdf3143e77f69265e09458a2b42b75b72680eb043da71e85"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, Tony Yeh" and pe.signatures[i].serial=="08:60:c8:a7:ed:18:c3:f0:30:a3:27:22:fd:2b:22:0c" and 1404172799<=pe.signatures[i].not_after)
}
