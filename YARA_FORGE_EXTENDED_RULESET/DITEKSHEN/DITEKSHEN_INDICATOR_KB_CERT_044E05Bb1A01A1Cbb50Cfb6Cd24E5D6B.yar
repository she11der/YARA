import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_044E05Bb1A01A1Cbb50Cfb6Cd24E5D6B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "e8dc8963-29c1-5306-bd7d-80ad9e1334d9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L367-L378"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c433b63f9c875a564f424ecc8e9239701ce8be78cd0046c1eefca8cf732abca3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "149b7bbe88d4754f2900c88516ce97be605553ff"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and pe.signatures[i].serial=="04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b")
}
