rule SIGNATURE_BASE_Cmd_Asp_5_1_Asp
{
	meta:
		description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "fc204ab8-892d-5435-a737-a185ca32e938"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4511-L4522"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
		logic_hash = "a41c83da1a65e67b6f4ac6ad7cc8702486957ab0c7dda658d071e603338c324b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
		$s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword

	condition:
		1 of them
}
