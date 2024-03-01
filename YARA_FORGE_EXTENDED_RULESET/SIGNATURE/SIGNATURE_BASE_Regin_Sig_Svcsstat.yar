rule SIGNATURE_BASE_Regin_Sig_Svcsstat : FILE
{
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		id = "0cb493d7-c7f1-54c4-9805-d9894bf399da"
		date = "2014-11-26"
		modified = "2023-12-15"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_regin_fiveeyes.yar#L126-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"
		logic_hash = "2b1fdc2cc8c0aedaf749ee0e87a8853b91735a4e215c65df221a930d4b1d02f7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "Service Control Manager" fullword ascii
		$s1 = "_vsnwprintf" ascii
		$s2 = "Root Agency" fullword ascii
		$s3 = "Root Agency0" fullword ascii
		$s4 = "StartServiceCtrlDispatcherA" fullword ascii
		$s5 = "\\\\?\\UNC" fullword wide
		$s6 = "%ls%ls" fullword wide

	condition:
		all of them and filesize <15KB and filesize >10KB
}
