import "pe"

rule REVERSINGLABS_Cert_Blocklist_62205361A758B00572D417Cba014F007 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "85da8e0e-d791-5fed-b9ea-c681462651a6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4142-L4158"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ebf28921c81191bcf6130baf6532122bb320cc916e38ab225f0acdcb57ea00f3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UNITEKH-S, OOO" and pe.signatures[i].serial=="62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07" and 1590470683<=pe.signatures[i].not_after)
}
