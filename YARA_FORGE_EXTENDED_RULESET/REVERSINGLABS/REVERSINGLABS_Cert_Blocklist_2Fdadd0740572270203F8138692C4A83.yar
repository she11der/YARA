import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Fdadd0740572270203F8138692C4A83 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0b289c4e-c564-5513-a1a5-42e8551c6218"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1600-L1616"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "18ce7ed721a454c5bb3cd6ab26df703b1e08b94b8c518055feffa38ad42afa50"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, William Zoltan" and pe.signatures[i].serial=="2f:da:dd:07:40:57:22:70:20:3f:81:38:69:2c:4a:83" and 1404172799<=pe.signatures[i].not_after)
}
