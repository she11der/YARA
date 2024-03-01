import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store : FILE
{
	meta:
		description = "Detects executables referencing many confidential data stores found in browsers, mail clients, cryptocurreny wallets, etc. Observed in information stealers"
		author = "ditekSHen"
		id = "07223564-bf4f-5fcd-ad3d-b67eb3baea8e"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L345-L359"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5350f79b01e8e8ae9e0607aa02965cd9ccc52c59a901abcb51e401476cb0fa3a"
		score = 40
		quality = 31
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "key3.db" nocase ascii wide
		$s2 = "key4.db" nocase ascii wide
		$s3 = "cert8.db" nocase ascii wide
		$s4 = "logins.json" nocase ascii wide
		$s5 = "account.cfn" nocase ascii wide
		$s6 = "wand.dat" nocase ascii wide
		$s7 = "wallet.dat" nocase ascii wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
