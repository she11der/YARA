rule DITEKSHEN_INDICATOR_KB_ID_Qakbot : FILE
{
	meta:
		description = "Detects QakBot executables with specific email addresses found in the code signing certificate"
		author = "ditekShen"
		id = "24ad36b2-5022-5f72-b01c-fbb64da20f34"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L23-L37"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7a38069b3b553cba1a789dac706638382dae5bb748b0c10ef50138879767b6dd"
		score = 75
		quality = 61
		tags = "FILE"

	strings:
		$s1 = "hutter.s94@yahoo.com" ascii wide nocase
		$s2 = "andrej.vrear@aol.com" ascii wide nocase
		$s3 = "klaus.pedersen@aol.com" ascii wide nocase
		$s4 = "a.spendl@aol.com" ascii wide nocase
		$s5 = "mjemec@aol.com" ascii wide nocase
		$s6 = "robert.sijanec@yahoo.com" ascii wide nocase
		$s7 = "mitja.vidovi@aol.com" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}
