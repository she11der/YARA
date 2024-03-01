import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICOUS_EXE_UNC_Regex : FILE
{
	meta:
		description = "Detects executables with considerable number of regexes often observed in infostealers"
		author = "ditekSHen"
		id = "968ed633-46ed-5efe-84e5-64718f89fb0a"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_suspicious.yar#L2267-L2296"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9201469952c2cacebbcbf6801e2c22d018f36742ffbefedc8ee4aa34f413334a"
		score = 75
		quality = 73
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "^((8|\\+7|\\+380|\\+375|\\+373)[\\- ]?)?(\\(?\\d{3}\\)?[\\- ]?)?[\\d\\- ]{7,10}$" ascii wide
		$s2 = "(^(1|3)(?=.*[0-9])(?=.*[a-zA-Z])[\\da-zA-Z]{27,34}?[\\d\\- ])|(^(1|3)(?=.*[0-9])(?=.*[a-zA-Z])[\\da-zA-Z]{27,34})$" ascii wide
		$s3 = "(^L[A-Za-z0-9]{32,34}?[\\d\\- ])|(^L[A-Za-z0-9]{32,34})$" ascii wide
		$s4 = "(^q[A-Za-z0-9\\:]{32,54}?[\\d\\- ])|(^q[A-Za-z0-9\\:]{32,54})$" ascii wide
		$s5 = "^(P|p){1}[0-9]?[\\d\\- ]{7,15}|.+@.+\\..+$" ascii wide
		$s6 = "(^0x[A-Za-z0-9]{40,42}?[\\d\\- ])|(^0x[A-Za-z0-9]{40,42})$" ascii wide
		$s7 = "(^X[A-Za-z0-9]{32,34}?[\\d\\- ])|(^X[A-Za-z0-9]{32,34})$" ascii wide
		$s8 = "^41001[0-9]?[\\d\\- ]{7,11}$" ascii wide
		$s9 = "^R[0-9]?[\\d\\- ]{12,13}$" ascii wide
		$s10 = "^Z[0-9]?[\\d\\- ]{12,13}$" ascii wide
		$s11 = "(^(GD|GC)[A-Z0-9]{54,56}?[\\d\\- ])|(^(GD|GC)[A-Z0-9]{54,56})$" ascii wide
		$s12 = "(^A[A-Za-z0-9]{32,34}?[\\d\\- ])|(^A[A-Za-z0-9]{32,34})$" ascii wide
		$s13 = "(^t[A-Za-z0-9]{32,36}?[\\d\\- ])|(^t[A-Za-z0-9]{32,36})$" ascii wide
		$s14 = "(^r[A-Za-z0-9]{32,34}?[\\d\\- ])|(^r[A-Za-z0-9]{32,34})$" ascii wide
		$s15 = "(^G[A-Za-z0-9]{32,35}?[\\d\\- ])|(^G[A-Za-z0-9]{32,35})$" ascii wide
		$s16 = "(^D[A-Za-z0-9]{32,35}?[\\d\\- ])|(^D[A-Za-z0-9]{32,35})$" ascii wide
		$s17 = "(^(T[A-Z])[A-Za-z0-9]{32,35}?[\\d\\- ])|(^(T[A-Z])[A-Za-z0-9]{32,35})$" ascii wide
		$s18 = "^1[a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii wide
		$s19 = "^3[a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii wide
		$s20 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" ascii wide
		$s21 = "^(?!:\\/\\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$" ascii wide
		$s22 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}|mfa\\.[\\w-]{84}" ascii wide

	condition:
		uint16(0)==0x5a4d and 6 of them
}
