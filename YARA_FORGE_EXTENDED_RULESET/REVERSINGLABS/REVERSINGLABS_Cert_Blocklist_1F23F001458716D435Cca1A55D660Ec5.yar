import "pe"

rule REVERSINGLABS_Cert_Blocklist_1F23F001458716D435Cca1A55D660Ec5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "16614e20-1cf1-55c0-a04c-d99c06fb29a2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5956-L5972"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bacfb4b7900ab57d23474e0422bd74fff113296b8db37e8eae3bd456443d28d6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Ringen" and pe.signatures[i].serial=="1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5" and 1603176940<=pe.signatures[i].not_after)
}
