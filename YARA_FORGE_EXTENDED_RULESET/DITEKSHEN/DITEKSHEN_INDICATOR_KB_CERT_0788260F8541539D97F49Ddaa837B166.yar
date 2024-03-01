import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0788260F8541539D97F49Ddaa837B166 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fb102e07-92fc-5ed8-a9cf-1cfd53f54281"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7253-L7265"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "48985ac2c450bc4b3c5de635717dcf3a7ecf64109aa4059477ba79606f7fc2a4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "569511fdc5e8dea454e97b005de1af5272d4bd32"
		hash1 = "6ad407d5c7e4574c7452a1a27da532ee9a55bb4074e43aa677703923909169e4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TechSmith Corporation" and pe.signatures[i].serial=="07:88:26:0f:85:41:53:9d:97:f4:9d:da:a8:37:b1:66")
}
