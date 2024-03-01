import "pe"

rule REVERSINGLABS_Cert_Blocklist_075Dca9Ca84B93E8A89B775128F90302 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2fa6b400-7c6c-5bc4-9cac-78d52003a24e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3716-L3732"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "32af21e71fb3475c50de4cd8a24fa0aec1ee67bc01c1a3720c12f9ce822833c3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UAB GT-servis" and pe.signatures[i].serial=="07:5d:ca:9c:a8:4b:93:e8:a8:9b:77:51:28:f9:03:02" and 1579305601<=pe.signatures[i].not_after)
}
