rule SIGNATURE_BASE_Nishang_Webshell : FILE
{
	meta:
		description = "Detects a ASPX web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "785e6da7-097e-598b-9799-ffe43738d718"
		date = "2016-09-11"
		modified = "2023-12-05"
		reference = "https://github.com/samratashok/nishang"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9660-L9675"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b8a3c8e80a4e41e556e2d65df4126d84723ded6ca623302afc4cc328bded346c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
		$s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
		$s3 = "<title>Antak Webshell</title>" fullword ascii
		$s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii

	condition:
		( uint16(0)==0x253C and filesize <100KB and 1 of ($s*))
}
