import "pe"

rule REVERSINGLABS_Cert_Blocklist_39F56251Df2088223Cc03494084E6081 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0c475e89-9729-53b9-a301-7a9faa0fef91"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3562-L3578"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c87850f91758a5bb3bdf6f6d7de9a3f53077d64cebdde541ac0742d3cea4f4e0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Inter Med Pty. Ltd." and pe.signatures[i].serial=="39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81" and 1583539200<=pe.signatures[i].not_after)
}
