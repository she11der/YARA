rule SIGNATURE_BASE_Hdroot_Sample_Jul17_2 : FILE
{
	meta:
		description = "Detects HDRoot samples"
		author = "Florian Roth (Nextron Systems)"
		id = "9ce9c0f4-e6f9-5033-ba74-367e6d741650"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "Winnti HDRoot VT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_winnti_hdroot.yar#L28-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "94288abb5c4da7c4b07eeae55070797af1556dac35ad012aff1bbe8c05e0a215"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1c302ed9786fc600073cc6f3ed2e50e7c23785c94a2908f74f92971d978b704b"
		hash2 = "3b7cfa40e26fb6b079b55ec030aba244a6429e263a3d9832e32ab09e7a3c4a9c"
		hash3 = "71eddf71a94c5fd04c9f3ff0ca1eb6b1770df1a3a8f29689fb8588427b5c9e8e"
		hash4 = "80e088f2fd2dbde0f9bc21e056b6521991929c4e0ecd3eb5833edff6362283f4"

	strings:
		$x1 = "http://microsoftcompanywork.htm" fullword ascii
		$x2 = "compose.aspx?s=%4X%4X%4X%4X%4X%4X" fullword ascii
		$t1 = "http://babelfish.yahoo.com/translate_url?" fullword ascii
		$t2 = "http://translate.google.com/translate?prev=hp&hl=en&js=n&u=%s?%d&sl=es&tl=en" fullword ascii
		$u1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.5." ascii
		$u2 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon)" fullword ascii
		$u3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon; TERA:" fullword ascii
		$s1 = "\\system32\\ntoskrnl.exe" ascii
		$s2 = "Schedsvc.dll" fullword wide
		$s3 = "dllserver64.dll" fullword ascii
		$s4 = "C:\\TERA_SR.txt" fullword ascii
		$s5 = "updatevnsc.dat" fullword wide
		$s6 = "tera dll service global event" fullword ascii
		$s7 = "Referer: http://%s/%s" fullword ascii
		$s8 = "tera replace dll config" fullword ascii
		$s9 = "SetupDll64.dll" fullword ascii
		$s10 = "copy %%ComSpec%% \"%s\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (1 of ($x*) or all of ($u*) or 8 of them )
}
