import "pe"

rule REVERSINGLABS_Cert_Blocklist_4728189Fa0F57793484Cdf764F5E283D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fd1b83aa-bfcc-590c-8f97-875badf09698"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11498-L11514"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9ec7e84c77583bd52ccfb8d6d5831f3634ed0a401d8103376c4775b7f2c43d81"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Power Save Systems s.r.o." and pe.signatures[i].serial=="47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d" and 1647302400<=pe.signatures[i].not_after)
}
