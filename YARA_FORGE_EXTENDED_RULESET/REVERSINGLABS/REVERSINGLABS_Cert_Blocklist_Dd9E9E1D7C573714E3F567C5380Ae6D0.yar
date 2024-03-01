import "pe"

rule REVERSINGLABS_Cert_Blocklist_Dd9E9E1D7C573714E3F567C5380Ae6D0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "72745795-0261-5b7b-b25e-8220bced90ec"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12724-L12742"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7bbcdb989d53bafbb2bdb694be72d4f7305323c01e8f1eafcb7cd889df165ff6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CREA&COM d.o.o." and (pe.signatures[i].serial=="00:dd:9e:9e:1d:7c:57:37:14:e3:f5:67:c5:38:0a:e6:d0" or pe.signatures[i].serial=="dd:9e:9e:1d:7c:57:37:14:e3:f5:67:c5:38:0a:e6:d0") and 1575849600<=pe.signatures[i].not_after)
}
