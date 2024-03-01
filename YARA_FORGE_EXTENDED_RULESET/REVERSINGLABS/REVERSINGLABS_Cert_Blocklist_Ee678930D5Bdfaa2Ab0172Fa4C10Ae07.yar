import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ee678930D5Bdfaa2Ab0172Fa4C10Ae07 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e2c2c34a-6177-5457-9ed9-fa34f82ee4cd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5346-L5364"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f1e254450fdbe94172a4fa2d2727c3ade5ae436cf4c0c1153a15e9a2f64f2452"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEX CORPORATION PTY LTD" and (pe.signatures[i].serial=="00:ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07" or pe.signatures[i].serial=="ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07") and 1571011200<=pe.signatures[i].not_after)
}
