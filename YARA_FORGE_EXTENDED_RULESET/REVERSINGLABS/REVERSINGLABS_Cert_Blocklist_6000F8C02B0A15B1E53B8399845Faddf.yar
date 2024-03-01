import "pe"

rule REVERSINGLABS_Cert_Blocklist_6000F8C02B0A15B1E53B8399845Faddf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b025fe73-89fa-55f2-8b3a-cb46251669e6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10498-L10514"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "00ceb241555154cab97ef616042dbd966f3a8fae257e142dfe6bad9559bd1724"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAY LIMITED" and pe.signatures[i].serial=="60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df" and 1644278400<=pe.signatures[i].not_after)
}
