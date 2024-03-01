import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_118D813D830F218C0F46D4Fc : FILE
{
	meta:
		description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
		author = "ditekSHen"
		id = "b14b14c8-202d-533d-97dc-c6336ddf75c4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2744-L2755"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3240504794394c06f050ef3eb5ef82e0b476e2bbeabfb394fc4646e98bc6e976"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bd16f70bf6c2ef330c5a4f3a27856a0d030d77fa"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shang Hai Shen Wei Wang Luo Ke Ji You Xian Gong Si" and pe.signatures[i].serial=="11:8d:81:3d:83:0f:21:8c:0f:46:d4:fc")
}
