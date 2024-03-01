import "pe"

rule REVERSINGLABS_Cert_Blocklist_33671F1Bcbd0F5E231Fc386F4895000E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0863e1ed-7b9c-5a60-82ac-eadc3c23fbd9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13728-L13744"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9199c8d76e3390ec9038808b4e88b803b3f3d6966af6206d0c9968d9ab673f31"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALAIS, OOO" and pe.signatures[i].serial=="33:67:1f:1b:cb:d0:f5:e2:31:fc:38:6f:48:95:00:0e" and 1491868800<=pe.signatures[i].not_after)
}
