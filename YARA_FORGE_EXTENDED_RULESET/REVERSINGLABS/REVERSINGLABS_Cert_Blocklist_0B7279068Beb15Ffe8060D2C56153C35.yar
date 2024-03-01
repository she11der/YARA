import "pe"

rule REVERSINGLABS_Cert_Blocklist_0B7279068Beb15Ffe8060D2C56153C35 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "78bfa550-d85e-5776-a65d-ff0039abd2c4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16320-L16336"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ca00f1adacd6ff16e54b85be38c3a4545a10c76548e0647f7f3f6cfa4dff412d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Guangzhou YuanLuo Technology Co.,Ltd" and pe.signatures[i].serial=="0b:72:79:06:8b:eb:15:ff:e8:06:0d:2c:56:15:3c:35" and 1350864000<=pe.signatures[i].not_after)
}
