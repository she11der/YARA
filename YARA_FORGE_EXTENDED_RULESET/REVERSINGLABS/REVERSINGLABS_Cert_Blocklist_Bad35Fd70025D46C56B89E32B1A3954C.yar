import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bad35Fd70025D46C56B89E32B1A3954C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "871e399f-8498-5d66-ab5e-24e48491124f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6656-L6674"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1020250fc5030e50bc1e7d0f0c5a77e462a53f47bfcc4383c682b34fed567492"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fort LLC" and (pe.signatures[i].serial=="00:ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c" or pe.signatures[i].serial=="ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c") and 1604937337<=pe.signatures[i].not_after)
}
