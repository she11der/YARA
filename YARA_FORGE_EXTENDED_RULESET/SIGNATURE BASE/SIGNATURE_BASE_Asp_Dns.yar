rule SIGNATURE_BASE_Asp_Dns : FILE
{
	meta:
		description = "Laudanum Injector Tools - file dns.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "b0e30ca0-7163-5731-98c5-5a1893b8ea80"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L280-L296"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
		logic_hash = "808e879238a0c24e975c260fc95c05c91bdc0f73553a241bd00f5bf7e6622639"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii
		$s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii
		$s3 = "Response.Write command & \"<br>\"" fullword ascii
		$s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii

	condition:
		filesize <21KB and all of them
}
