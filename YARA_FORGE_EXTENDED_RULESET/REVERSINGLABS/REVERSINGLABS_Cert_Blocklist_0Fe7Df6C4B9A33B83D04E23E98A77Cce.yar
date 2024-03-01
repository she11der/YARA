import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fe7Df6C4B9A33B83D04E23E98A77Cce : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "47a10658-c5c4-58b6-b154-7babcfbc50a2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1144-L1160"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "da5ed07def8d0c04ea58aacd90f9fa5588f868f6d0057b9148587f2f0b381f25"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PIXELPLUS CO., LTD." and pe.signatures[i].serial=="0f:e7:df:6c:4b:9a:33:b8:3d:04:e2:3e:98:a7:7c:ce" and 1396310399<=pe.signatures[i].not_after)
}
