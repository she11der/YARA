rule SIGNATURE_BASE_Dll_Loadex : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "51235448-751e-51ce-93f8-da48eddb2b7f"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L584-L603"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"
		logic_hash = "588f4f4d0a2f8f8e76de0a5b1217191c1cace69f934582d4fc3c974fb94b8c3e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "WiNrOOt@126.com" fullword wide
		$s1 = "Dll_LoadEx.EXE" fullword wide
		$s3 = "You Already Loaded This DLL ! :(" ascii
		$s10 = "Dll_LoadEx Microsoft " fullword wide
		$s17 = "Can't Load This Dll ! :(" ascii
		$s18 = "WiNrOOt" fullword wide
		$s20 = " Dll_LoadEx(&A)..." fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <120KB and 3 of them
}
