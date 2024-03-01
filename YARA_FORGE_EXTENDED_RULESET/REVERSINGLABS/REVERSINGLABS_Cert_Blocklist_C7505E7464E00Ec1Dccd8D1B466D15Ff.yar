import "pe"

rule REVERSINGLABS_Cert_Blocklist_C7505E7464E00Ec1Dccd8D1B466D15Ff : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a75cc09f-de73-5db4-9ace-189e8da99053"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3616-L3634"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7c5c84cb9071eff6a1bd7062506b807466bb4a432d1ed073961898c6c08cc4bd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (pe.signatures[i].serial=="00:c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff" or pe.signatures[i].serial=="c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff") and 1583824676<=pe.signatures[i].not_after)
}
