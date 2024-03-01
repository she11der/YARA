rule SIGNATURE_BASE_Apt_Backspace : FILE
{
	meta:
		description = "Detects APT backspace"
		author = "Bit Byte Bitten"
		id = "3da3337d-b6d3-5661-b43e-535e06817303"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_backspace.yar#L6-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"
		logic_hash = "6fa86ada5c965bd9c199c2a1cf9b691499a3d423da7db50c8987b6725c0c0f29"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "!! Use Splice Socket !!"
		$s2 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
		$s3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"

	condition:
		uint16(0)==0x5a4d and all of them
}
