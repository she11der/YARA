import "pe"

rule REVERSINGLABS_Cert_Blocklist_06477E3425F1448995Ced539789E6842 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "21da6056-bf4e-5fc4-bef5-37010ebe8f05"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L531-L547"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c0bc7808bb6bcc8273a887203c1b47d1a49fcb7719863e6bc97b5c7404a254f7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Karim Lammali" and pe.signatures[i].serial=="06:47:7e:34:25:f1:44:89:95:ce:d5:39:78:9e:68:42" and 1334275199<=pe.signatures[i].not_after)
}
