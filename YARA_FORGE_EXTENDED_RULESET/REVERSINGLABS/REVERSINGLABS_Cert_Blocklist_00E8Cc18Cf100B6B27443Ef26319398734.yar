import "pe"

rule REVERSINGLABS_Cert_Blocklist_00E8Cc18Cf100B6B27443Ef26319398734 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "f7e80c51-9dcf-599a-8164-c07cf4c9c5ff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1434-L1452"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "68e9df056109cae41d981090c7a98ddc192a445647d7475569ddbe4118e570c5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Syngenta" and (pe.signatures[i].serial=="00:e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34" or pe.signatures[i].serial=="e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34") and 1404172799<=pe.signatures[i].not_after)
}
