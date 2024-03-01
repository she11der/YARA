rule SIGNATURE_BASE_SUSP_Excel4Macro_Autoopen : FILE
{
	meta:
		description = "Detects Excel4 macro use with auto open / close"
		author = "John Lambert @JohnLaTwC"
		id = "cfed97fe-b330-5528-8402-08c6ba6af04a"
		date = "2020-03-26"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_Excel4Macro_Sharpshooter.yar#L27-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
		logic_hash = "074aab8e1d3b66e34e8e8d8e8489e1dfee1091df0424b22cd1bfd3cf904754e1"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$header_docf = { D0 CF 11 E0 }
		$s1 = "Excel" fullword
		$Auto_Open = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
		$Auto_Close = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
		$Auto_Open1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
		$Auto_Close1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }

	condition:
		filesize <3000KB and $header_docf at 0 and $s1 and any of ($Auto_*)
}
