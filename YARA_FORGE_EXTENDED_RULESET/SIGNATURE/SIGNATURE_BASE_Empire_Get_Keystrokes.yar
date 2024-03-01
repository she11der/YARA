rule SIGNATURE_BASE_Empire_Get_Keystrokes : FILE
{
	meta:
		description = "Detects Empire component - file Get-Keystrokes.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "7fb57a0d-6b65-5ee8-96ef-9af303f15007"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L307-L320"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "710e1bbf517c6683bd3082786e605cb8e6a52460f9c96609610e5ab38800dc79"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"

	strings:
		$s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
