import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fa3Dcac19B884B44Ef4F81541184D6B0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "574ee0d4-ba7c-5c74-b711-222f92196f4a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6808-L6826"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "324de84cb8c2f5402c9326749e3456e11312828df2523954fd84f7fb3298fdf3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unicom Ltd" and (pe.signatures[i].serial=="00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0" or pe.signatures[i].serial=="fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0") and 1603958571<=pe.signatures[i].not_after)
}
