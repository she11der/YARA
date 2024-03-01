import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F62F760704Bdf8Dc30C7Baa7376F484 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fe326fb9-fe1e-5fc9-8599-6b4cfd6506dd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12406-L12422"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d54d52e116b9404782ce80664f218d2e142577dac672c53c41b82f0466c7375a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shanghai XuSong investment partnership Enterprise(Limited)" and pe.signatures[i].serial=="0f:62:f7:60:70:4b:df:8d:c3:0c:7b:aa:73:76:f4:84" and 1659398400<=pe.signatures[i].not_after)
}
