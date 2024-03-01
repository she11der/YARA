import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Bd55818C5971B63Dc45Cf57Cbeb950B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Derusbi malware."
		author = "ReversingLabs"
		id = "9269cc5c-039e-5d98-ac13-c7b99606e7fa"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2032-L2048"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5aa41a2d6a86a30559b36818602e1bdf2bfd38b799a4869c26c150052d6d788c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "XL Games Co.,Ltd." and pe.signatures[i].serial=="7b:d5:58:18:c5:97:1b:63:dc:45:cf:57:cb:eb:95:0b" and 1371513599<=pe.signatures[i].not_after)
}
