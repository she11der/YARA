rule AVASTTI_Cobaltstrike_Beacon_Encoded
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "497e2a32-015a-5786-a6fa-de7084bfc389"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L653-L703"
		license_url = "N/A"
		logic_hash = "f763c0c41a69c6bafb65517d20ef76242bf7b1626d6745d9a1c26772de3ffa26"
		score = 75
		quality = 68
		tags = ""

	strings:
		$s01 = "0x4d, 0x5a, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x89, 0xdf, 0x52, 0x45, 0x55, 0x89, 0xe5, 0x81" ascii wide nocase
		$s02 = "0x4d,0x5a,0xe8,0x00,0x00,0x00,0x00,0x5b,0x89,0xdf,0x52,0x45,0x55,0x89,0xe5,0x81" ascii wide nocase
		$s03 = "0x4d, 0x5a, 0x41, 0x52, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x20, 0x00, 0x00, 0x00, 0x48" ascii wide nocase
		$s04 = "0x4d,0x5a,0x41,0x52,0x55,0x48,0x89,0xe5,0x48,0x81,0xec,0x20,0x00,0x00,0x00,0x48" ascii wide nocase
		$s05 = "4d5ae8000000005b89df52455589e581" ascii wide nocase
		$s06 = "4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81" ascii wide nocase
		$s07 = "4d5a4152554889e54881ec2000000048" ascii wide nocase
		$s08 = "4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48" ascii wide nocase
		$s09 = "TVroAAAAAFuJ31JFVYnlg" ascii wide
		$s10 = "TVpBUlVIieVIgewgAAAAS" ascii wide
		$s11 = "bnnLIyMjI3iq/HFmdqrGo" ascii wide
		$s12 = "bnlicXZrqsZros8DIyMja" ascii wide
		$s13 = "TQBaAOgAAAAAAAAAAABbAIkA3wBSAEUAVQCJAOUAg" ascii wide
		$s14 = "TQBaAEEAUgBVAEgAiQDlAEgAgQDsACAAAAAAAAAAS" ascii wide
		$s15 = "biN5I2IjcSN2I2sjqiPGI2sjoiPPIwMjIyMjIyMja" ascii wide
		$s16 = "biN5I8sjIyMjIyMjIyN4I6oj/CNxI2YjdiOqI8Yjo" ascii wide
		$s17 = "Array(77,90,-24,0,0,0,0,91,-119,-33,82,69,85,-119,-27,-127" ascii wide
		$s18 = "Array(77, 90, -24, 0, 0, 0, 0, 91, -119, -33, 82, 69, 85, -119, -27, -127" ascii wide
		$s19 = "Array(77,90,65,82,85,72,-119,-27,72,-127,-20,32,0,0,0,72" ascii wide
		$s20 = "Array(77, 90, 65, 82, 85, 72, -119, -27, 72, -127, -20, 32, 0, 0, 0, 72" ascii wide
		$s21 = "MZ\"&Chr(-27)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(91)&Chr(-119)&Chr(-33)&\"REU\"&Chr(-119)&Chr(-27)&Chr(-127)" ascii wide
		$s22 = "MZARUH\"&Chr(-119)&Chr(-27)&\"H\"&Chr(-127)&Chr(-20)&Chr(32)&Chr(0)&Chr(0)&Chr(0)&\"H" ascii wide
		$s23 = "\\x4d\\x5a\\xe8\\x00\\x00\\x00\\x00\\x5b\\x89\\xdf\\x52\\x45\\x55\\x89\\xe5\\x81" ascii wide nocase
		$s24 = "\\x4d\\x5a\\x41\\x52\\x55\\x48\\x89\\xe5\\x48\\x81\\xec\\x20\\x00\\x00\\x00\\x48" ascii wide nocase

	condition:
		any of them
}
