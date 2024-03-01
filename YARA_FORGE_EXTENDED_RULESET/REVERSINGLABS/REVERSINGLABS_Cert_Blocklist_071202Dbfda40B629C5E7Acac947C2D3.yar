import "pe"

rule REVERSINGLABS_Cert_Blocklist_071202Dbfda40B629C5E7Acac947C2D3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4206c383-0e6d-5129-8e6a-05bd54c48e65"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12424-L12440"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cc51b0ae6a59f68e61ee0b4ff33ea0e1ee9ef04e4c994e1c98da6befab62a5b9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Crossfire Industries, LLC" and pe.signatures[i].serial=="07:12:02:db:fd:a4:0b:62:9c:5e:7a:ca:c9:47:c2:d3" and 1658620801<=pe.signatures[i].not_after)
}
