import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bc6C43D206A360F2D6B58537C456B709 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fd19ce61-056b-549a-946e-72543ff1f7c0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12274-L12292"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "eb5288d2b96ff7a7783c2b2b02f9f1168784352ed84ad6463dce00c12daca6cb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ANKADA GROUP, d.o.o." and (pe.signatures[i].serial=="00:bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09" or pe.signatures[i].serial=="bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09") and 1616630400<=pe.signatures[i].not_after)
}
