import "pe"

rule REVERSINGLABS_Cert_Blocklist_12Df5Ff3460979Cec1288D874A9Fbf83 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9158c9a5-37fc-54bc-9601-3aa347a421ab"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10806-L10822"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3d4b5e56962d04bc35451eeab4c1870c8653c9afcbb28dc6bad7cfb1711e9df1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and pe.signatures[i].serial=="12:df:5f:f3:46:09:79:ce:c1:28:8d:87:4a:9f:bf:83" and 1599091200<=pe.signatures[i].not_after)
}
