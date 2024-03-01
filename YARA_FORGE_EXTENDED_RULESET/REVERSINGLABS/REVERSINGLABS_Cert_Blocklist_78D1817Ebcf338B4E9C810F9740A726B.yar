import "pe"

rule REVERSINGLABS_Cert_Blocklist_78D1817Ebcf338B4E9C810F9740A726B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3d0a97a4-c45a-5238-a287-867529b470cb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13674-L13690"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "62e59130ef0ac35b17a265bb8bc2031cac6a75c11925ccb21eb4601b8fbe1a63"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CONSTRUTORA NOVO PARQUE LTDA - ME" and pe.signatures[i].serial=="78:d1:81:7e:bc:f3:38:b4:e9:c8:10:f9:74:0a:72:6b" and 1431734400<=pe.signatures[i].not_after)
}
