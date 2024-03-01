import "pe"

rule REVERSINGLABS_Cert_Blocklist_B7F19B13De9Bee8A52Ff365Ced6F67Fa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0e7e235e-3f0b-5396-9c19-9336d9cbb95a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6328-L6346"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a8d2a92b44cdd7b123907a6a77ba0fc9fde4961f9ac846b36f1e87730a1efae6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and (pe.signatures[i].serial=="00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa" or pe.signatures[i].serial=="b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa") and 1574914319<=pe.signatures[i].not_after)
}
