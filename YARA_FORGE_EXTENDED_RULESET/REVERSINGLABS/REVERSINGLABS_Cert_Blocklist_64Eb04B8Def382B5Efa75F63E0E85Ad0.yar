import "pe"

rule REVERSINGLABS_Cert_Blocklist_64Eb04B8Def382B5Efa75F63E0E85Ad0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5f4da614-3bc8-5ae8-b04b-e4b3972522ff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15738-L15754"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "03adb8a9bf2a8f0633b34d5c39816b47e60b9e598208f7de79ad9d9a7ab8cc5e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOV \"MARIYA\"" and pe.signatures[i].serial=="64:eb:04:b8:de:f3:82:b5:ef:a7:5f:63:e0:e8:5a:d0" and 1535587200<=pe.signatures[i].not_after)
}
