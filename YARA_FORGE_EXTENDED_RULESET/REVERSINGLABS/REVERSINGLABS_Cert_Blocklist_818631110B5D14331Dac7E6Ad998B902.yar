import "pe"

rule REVERSINGLABS_Cert_Blocklist_818631110B5D14331Dac7E6Ad998B902 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6a8f3abd-199c-5e2f-a60e-46e869831445"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8638-L8656"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5e0de3848adf933632c2eb8cf5ead61d6470237386ba8b48d57a278d99dba324"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2 TOY GUYS LLC" and (pe.signatures[i].serial=="00:81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02" or pe.signatures[i].serial=="81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02") and 1571616000<=pe.signatures[i].not_after)
}
