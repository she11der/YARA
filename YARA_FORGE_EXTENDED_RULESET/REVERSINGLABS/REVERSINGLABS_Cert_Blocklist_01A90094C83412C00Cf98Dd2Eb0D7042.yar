import "pe"

rule REVERSINGLABS_Cert_Blocklist_01A90094C83412C00Cf98Dd2Eb0D7042 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e5059974-9ea2-5497-a728-c21a6cdd30e4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L405-L421"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5a3de0e6de5cda39e40988f9e2324cbee3e059aff5ceaf7fd819de8bf7215808"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FreeVox SA" and pe.signatures[i].serial=="01:a9:00:94:c8:34:12:c0:0c:f9:8d:d2:eb:0d:70:42" and 1376956799<=pe.signatures[i].not_after)
}
