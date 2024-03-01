import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_NKN_BCP2P : FILE
{
	meta:
		description = "Detects executables referencing NKN Blockchain P2P network"
		author = "ditekSHen"
		id = "21aa4034-8c8f-515e-b8a4-4ce32ad816a6"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2068-L2084"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "98161fcac130ba758bd9f8c4bc7133b9ba862df61dd86ad7d0ecbb0f18813a5e"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$x1 = "/nknorg/nkn-sdk-go." ascii
		$x2 = "://seed.nkn.org" ascii
		$x3 = "/nknorg/nkn/" ascii
		$s1 = ").NewNanoPayClaimer" ascii
		$s2 = ").IncrementAmount" ascii
		$s3 = ").BalanceByAddress" ascii
		$s4 = ").TransferName" ascii
		$s5 = ".GetWsAddr" ascii
		$s6 = ".GetNodeStateContext" ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or all of ($s*))
}
